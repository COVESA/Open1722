/*
 * Copyright (c) 2024, COVESA
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA nor the names of its contributors may be 
 *      used to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <locale.h>

#include "common/common.h"
#include "avtp/Udp.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Can.h"
#include "avtp/CommonHeader.h"

#define MAX_PDU_SIZE                1500
#define STREAM_ID                   0xAABBCCDDEEFF0001
#define CAN_PAYLOAD_MAX_SIZE        16*4

static char ifname[IFNAMSIZ];
static uint8_t macaddr[ETH_ALEN];
static uint8_t ip_addr[sizeof(struct in_addr)];
static uint32_t udp_port=17220;
static int priority = -1;
static uint8_t seq_num = 0;
static uint8_t use_tscf;
static uint8_t use_udp;
static char can_ifname[IFNAMSIZ] = "STDIN\0";
static bool timeout_flag = false;            // true when user supplies
static bool count_flag = false;              //    cmd line arg
static uint32_t buf_timeout = 0;             // override with --timeout
static uint32_t buf_can_frames = 1;          // override with --count
volatile sig_atomic_t send_ethernet = false; // true on timeout interrupt
struct itimerval timer;                      // used when --timeout given

static char doc[] =
"\n"
"acf-can-talker -- a program designed to send CAN messages to a remote CAN bus\n"
"                  over Ethernet using Open1722. The default behavior is to\n"
"                  send one CAN frame per Ethernet frame. However, a buffer can\n"
"                  be used that gives the opportunity to pack more than one.\n"
"\n"
"OPTIONS\n"
"\vBUFFERING\n\n"
"  acf-can-talker, by default, packs only one CAN frame into an Ethernet frame.\n"
"  Use the --timeout and/or --count options to change this behavior.\n\n"
"  --timeout <time>   where <time> is an integer followed by units, \n"
"                     e.g., '1s', or '400us'. Allowable units: 's', 'ms', 'us'.\n"
"                     The Ethernet frame will be sent <time> after arrival \n"
"                     of the first CAN message.\n\n"
"  --count <count>    where <count> is the max number of CAN frames allowed in \n"
"                     an Ethernet frame.\n\n"
"  If both buffering options are presented, then whichever occurs first will\n"
"  trigger the sending of the Ethernet frame.\n\n"
"  In all cases, when the Ethernet frame is full it is sent.\n\n"
"EXAMPLES\n"
"  acf-can-talker eth0 aa:bb:cc:ee:dd:ff\n\n"
"    (tunnel transactions from STDIN to a remote CAN bus over Ethernet)\n\n\n"
"  acf-can-talker --count 10 eth0 aa:bb:cc:ee:dd:ff\n\n"
"    (as above, but send Ethernet frame as soon as we have 10 CAN frames)\n\n\n"
"  acf-can-talker --timeout 400ms eth0 aa:bb:cc:ee:dd:ff\n\n"
"    (as above, but send Ethernet frame when 400 msec have passed since \n"
"     arrival of first CAN frame) \n\n\n"
"  acf-can-talker -u 10.0.0.2:17220 vcan1\n\n"
"    (tunnel transactions from can1 interface to a remote CAN bus over IP)\n\n\n"
"  candump can1 | acf-can-talker -u 10.0.0.2:17220\n\n"
"    (another method to tunnel transactions from vcan1 to a remote CAN bus)\n\n\n";

static char args_doc[] = "[ifname] dst-mac-address/dst-nw-address:port [can ifname]";

static struct argp_option options[] = {            
    {"tscf", 't', 0, 0, "Use TSCF"},
    {"udp",  'u', 0, 0, "Use UDP" },
    {"timeout", 501, "TIME", 0, "Set time to wait for CAN messages to arrive"},
    {"count", 502, "COUNT", 0, "Set count of CAN messages per Ethernet frame"},
    {"can ifname", 0, 0, OPTION_DOC, "CAN interface (set to STDIN by default)"},
    {"ifname", 0, 0, OPTION_DOC, "Network interface (If Ethernet)"},
    {"dst-mac-address", 0, 0, OPTION_DOC, "Stream destination MAC address (If Ethernet)"},
    {"dst-nw-address:port", 0, 0, OPTION_DOC, "Stream destination network address and port (If UDP)"},    
    { 0 }
};

static error_t parser(int key, char *arg, struct argp_state *state)
{
    int res;
    char ip_addr_str[100];

    switch (key) {
    case 't':
        use_tscf = 1;
        break;
    case 'u':
        use_udp = 1;
        break;
    case 501:
        char units[3];
        sscanf(arg, "%d%2s", &buf_timeout, units);
        if (strcmp(units, "s") == 0) {
            timer.it_value.tv_sec = buf_timeout;
            timer.it_value.tv_usec = 0;
        } else if (strcmp(units, "ms") == 0) {
            timer.it_value.tv_sec = floor(buf_timeout/1e3);
            timer.it_value.tv_usec = (buf_timeout % 1000) * 1000;
        } else if (strcmp(units, "us") == 0) {
            timer.it_value.tv_sec = floor(buf_timeout/1e6);
            timer.it_value.tv_usec = (buf_timeout % (uint32_t)1e6);
        } else { 
           fprintf(stderr, "error with timeout arg format; got: [%s]\n", arg);
           argp_usage(state);
        }
        timeout_flag = true;
        break;
    case 502:
        buf_can_frames = atoi(arg);
        count_flag = true;
        break;

    case ARGP_KEY_NO_ARGS:
        argp_usage(state);

    case ARGP_KEY_ARG:

        if(state->argc < 2){
            argp_usage(state);
        }    

        if(!use_udp){

            strncpy(ifname, arg, sizeof(ifname) - 1);       

            if(state->next < state->argc)
            {             
                res = sscanf(state->argv[state->next], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &macaddr[0], &macaddr[1], &macaddr[2],
                        &macaddr[3], &macaddr[4], &macaddr[5]);
                if (res != 6) {
                    fprintf(stderr, "Invalid MAC address\n\n");
                    argp_usage(state);
                }
                state->next += 1;   
            }

        } else {
            res = sscanf(arg, "%[^:]:%d", ip_addr_str, &udp_port);
            if (!res) {
                fprintf(stderr, "Invalid IP address or port\n\n");
                argp_usage(state);
            }
            res = inet_pton(AF_INET, ip_addr_str, ip_addr);
            if (!res) {
                fprintf(stderr, "Invalid IP address\n\n");
                argp_usage(state);
            }
        } 
          
        if(state->next < state->argc)
        {                                   
            strncpy(can_ifname, state->argv[state->next], sizeof(can_ifname) - 1);            
            state->next = state->argc;
        }         

        break;
    }

    return 0;
}

static struct argp argp = { options, parser, args_doc, doc };

static int init_cf_pdu(uint8_t* pdu)
{
    int res;
    if (use_tscf) {
        Avtp_Tscf_t* tscf_pdu = (Avtp_Tscf_t*) pdu;
        memset(tscf_pdu, 0, AVTP_TSCF_HEADER_LEN);
        Avtp_Tscf_Init(tscf_pdu);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_TU, 0U);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_SEQUENCE_NUM, seq_num++);
        Avtp_Tscf_SetField(tscf_pdu, AVTP_TSCF_FIELD_STREAM_ID, STREAM_ID);
        res = AVTP_TSCF_HEADER_LEN;
    } else {
        Avtp_Ntscf_t* ntscf_pdu = (Avtp_Ntscf_t*) pdu;
        memset(ntscf_pdu, 0, AVTP_NTSCF_HEADER_LEN);
        Avtp_Ntscf_Init(ntscf_pdu);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_SEQUENCE_NUM, seq_num++);
        Avtp_Ntscf_SetField(ntscf_pdu, AVTP_NTSCF_FIELD_STREAM_ID, STREAM_ID);
        res = AVTP_NTSCF_HEADER_LEN;
    }
    return res;
}

static int update_pdu_length(uint8_t* pdu, uint64_t length)
{
    if (use_tscf) {
        uint64_t payloadLen = length - AVTP_TSCF_HEADER_LEN;
        Avtp_Tscf_SetField((Avtp_Tscf_t*)pdu, AVTP_TSCF_FIELD_STREAM_DATA_LENGTH, payloadLen);
    } else {
        uint64_t payloadLen = length - AVTP_NTSCF_HEADER_LEN;
        Avtp_Ntscf_SetField((Avtp_Ntscf_t*)pdu, AVTP_NTSCF_FIELD_NTSCF_DATA_LENGTH, payloadLen);
    }
    return 0;
}

static int prepare_acf_packet(uint8_t* acf_pdu,
                          uint8_t* payload, uint8_t length,
                          uint32_t can_frame_id) {

    int processedBytes;
    struct timespec now;
    Avtp_Can_t* pdu = (Avtp_Can_t*) acf_pdu;

    // Clear bits
    memset(pdu, 0, AVTP_CAN_HEADER_LEN);

    // Prepare ACF PDU for CAN
    Avtp_Can_Init(pdu);
    clock_gettime(CLOCK_REALTIME, &now);
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MESSAGE_TIMESTAMP, (uint64_t)now.tv_nsec + (uint64_t)(now.tv_sec * 1e9));
    Avtp_Can_SetField(pdu, AVTP_CAN_FIELD_MTV, 1U);

    // Copy payload to ACF CAN PDU
    processedBytes = Avtp_Can_SetPayload(pdu, can_frame_id, payload, length, CAN_CLASSIC);

    return processedBytes;
}

static int get_payload(int can_socket, uint8_t* payload, uint32_t *frame_id, uint8_t *length) {

  char stdin_str[1000];
  char can_str[10];
  char can_payload[1000];
  char *token;
  size_t n;
  int res;
	struct can_frame frame;

  if (can_socket == 0) {
      n = read(STDIN_FILENO, stdin_str, 1000);    // EINTR detects interrupt
      if (n == -1 && errno == EINTR) {            // (our timeout)
          return -1;
      } else if (n < 0) {                         // other failure
        return -2;
      }

      res = sscanf(stdin_str, "%s %x [%hhu] %[0-9A-F ]s", can_str, frame_id,
                                                      length, can_payload);
      if (res < 0) {
          return -1;
      }

      token = strtok(can_payload, " ");
      int index = 0;
      while (token != NULL) {
          payload[index++] = (unsigned short)strtol(token, NULL, 16);
          token = strtok(NULL, " ");
      }
  } else {
      n = read(can_socket, &frame, sizeof(struct can_frame));
      if (n > 0) {
          *frame_id = (uint32_t) frame.can_id;
          *length = (uint8_t) frame.can_dlc;
          memcpy(payload, frame.data, (size_t) *length);
      } else if (n == -1 && errno == EINTR) {   // detect our timeout
        return -1;
      } else {
        return -1;
      }
  }
  
  return n;
}

// On timeout signal set a flag for our read loop to detect
void handle_timeout(int signum) {
  send_ethernet = true;
}

// Set a signal handler. This is a little more complicated than "normal"... in
// that we need to prevent an interrupted system call (like 'read') from being
// restarted. This function comes from 'Advanced Programming in the UNIX
// Environment', figure 10.19.
typedef void Sigfunc(int);
Sigfunc * signal_intr(int signo, Sigfunc *func) {
  struct sigaction act, oact;
  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
#ifdef  SA_INTERRUPT
  act.sa_flags |= SA_INTERRUPT;
#endif
  if (sigaction(signo, &act, &oact) < 0) 
    return(SIG_ERR);
  return(oact.sa_handler);
}



int main(int argc, char *argv[])
{

    int fd, res;
    struct sockaddr_ll sk_ll_addr;
    struct sockaddr_in sk_udp_addr;
    uint8_t pdu[MAX_PDU_SIZE];

    uint8_t payload[CAN_PAYLOAD_MAX_SIZE];
    uint8_t payload_length = 0;
    uint32_t frame_id = 0;
    uint32_t num_acf_msgs = 1;
    uint32_t pdu_length;

    int can_socket = 0;
	  struct sockaddr_can can_addr;
	  struct ifreq ifr;

    struct timespec start_time, end_time;    // for debugging --timeout
    setlocale(LC_NUMERIC, "");               // allow comma separator in printf

    // used to timeout the packing of Ethernet frame with CAN frames
    if (signal_intr(SIGALRM, handle_timeout) == SIG_ERR)
      perror("main(), setting handler: \n");

    argp_parse(&argp, argc, argv, 0, NULL, NULL);

    if (use_udp) {
        fd = create_talker_socket_udp(priority);
    } else {
        fd = create_talker_socket(priority);
    }
    if (fd < 0)
        return 1;

    // enforce timeout and count constraints, as requested
    if      (!timeout_flag && !count_flag) { num_acf_msgs = 1; }
    else if (!timeout_flag &&  count_flag) { num_acf_msgs = buf_can_frames; } 
    else if ( timeout_flag && !count_flag) { num_acf_msgs = 2^32 - 1; }
    else                                   { num_acf_msgs = buf_can_frames; } 

    // Open a CAN socket for reading frames if required
    if (strcmp(can_ifname, "STDIN\0")) {
        can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
        if (can_socket < 0)
            return 1;

        strcpy(ifr.ifr_name, can_ifname);
        ioctl(can_socket, SIOCGIFINDEX, &ifr);

        memset(&can_addr, 0, sizeof(can_addr));
        can_addr.can_family = AF_CAN;
        can_addr.can_ifindex = ifr.ifr_ifindex;
        if (bind(can_socket, (struct sockaddr *)&can_addr, sizeof(can_addr)) < 0) 
            return 1;
    }


    if (use_udp) {
        res = setup_udp_socket_address((struct in_addr*) ip_addr,
                                       udp_port, &sk_udp_addr);
        if (res < 0)
            goto err;
    } else {
        res = setup_socket_address(fd, ifname, macaddr, ETH_P_TSN, &sk_ll_addr);
        if (res < 0)
            goto err;
    }

    // Sending loop
    for(;;) {

        // Pack into control formats
        uint8_t *cf_pdu;
        pdu_length = 0;

        if (use_udp) {
            Avtp_UDP_t *udp_pdu = (Avtp_UDP_t *) pdu;
            Avtp_UDP_SetField(udp_pdu, AVTP_UDP_FIELD_ENCAPSULATION_SEQ_NO,
                              seq_num);
            cf_pdu = &pdu[sizeof(Avtp_UDP_t)];
        } else {
            cf_pdu = pdu;
        }

        res = init_cf_pdu(cf_pdu);
        if (res < 0)
            goto err;
        pdu_length += res;

        
        bool first_msg_is_next = true;
        int i = 1;
        // Get payload -- will loop here until we get the requested number
        //                of CAN frames, or until timeout.
        // magic numbers for detecting no more room in the Ethernet frame:
        // * 24 is max for CLASSIC CAN (CAN MESSAGE INFO + CAN BASE MESSAGE = 16 + 8)
        // * 80 is max for CAN FD (CAN MESSAGE INFO + CAN BASE MESSAGE = 16 + 64)
        // and then + 4 when using UDP, so 28 or 84 are the valid magic numbers.
        while ((i < num_acf_msgs) && (pdu_length < MAX_PDU_SIZE - 28 )) {

            if (send_ethernet) {
              //printf("timer interrupt: send_ethernet flag set; so send Ethernet\n"); fflush(stdout);
              send_ethernet = false;
              int width = 30;
              if (res >= 0)
                width+=(40-i);
              fprintf(stderr, "%*s", width, "detect send_ethernet flag");
              break;
            }
            
            //clock_gettime(CLOCK_REALTIME, &start_time);
            res = get_payload(can_socket, payload, &frame_id, &payload_length);
            if (res < 0) { 
              fprintf(stderr, "%*s", 40-i, "read() < 0");
              continue;
            } else if (res == 0)
              fprintf(stderr, "*");
            else
              fprintf(stderr, "%d", i);


            //clock_gettime(CLOCK_REALTIME, &end_time);
            // Calculate the elapsed time in seconds and nanoseconds
            //long elapsed_sec = end_time.tv_sec - start_time.tv_sec;
            //long elapsed_nsec = end_time.tv_nsec - start_time.tv_nsec;
            //if (elapsed_nsec < 0) {
            //    elapsed_sec--;
            //    elapsed_nsec += 1000000000;
            //}

            // Print the elapsed time
            //fprintf(stderr, "msg[%2d] res = [%d]   ", i, res);
            //fprintf(stderr, "Elapsed time: %ld s %'11ld nsec\n", elapsed_sec, elapsed_nsec);
            //fflush(stderr);

           
            // on reception of 1st msg we need to set our timer if we allow more
            // than one message per ethernet frame
            if (first_msg_is_next && num_acf_msgs > 1) {
                res = setitimer(ITIMER_REAL, &timer, NULL);
                //printf("timer is set: sec [%ld] usec [%ld]\n", 
                //       timer.it_value.tv_sec, timer.it_value.tv_usec); fflush(stdout);
                first_msg_is_next = false;
            }

            uint8_t* acf_pdu = cf_pdu + pdu_length;
            res = prepare_acf_packet(acf_pdu, payload, payload_length, frame_id);
            if (res < 0)
                goto err;
            pdu_length += res;

            i++;
        }

        //
        // done reading CAN for this Ethernet frame
        //

        fprintf(stderr, "\n");
        fflush(stderr);
        alarm(0);      // disarm timer 
        //printf("should send Ethernet here\n");fflush(stdout);

        res = update_pdu_length(cf_pdu, pdu_length);
        if (res < 0)
            goto err;

        if (use_udp) {
            pdu_length += sizeof(uint32_t);
            res = sendto(fd, pdu, pdu_length, 0,
                    (struct sockaddr *) &sk_udp_addr, sizeof(sk_udp_addr));
            if (res < 0) {
                perror("Failed to send data");
                goto err;
            }
        } else {
            res = sendto(fd, pdu, pdu_length, 0,
                         (struct sockaddr *) &sk_ll_addr, sizeof(sk_ll_addr));
            if (res < 0) {
                perror("Failed to send data");
                goto err;
            }
        }
    }

err:
    close(fd);
    return 1;

}
