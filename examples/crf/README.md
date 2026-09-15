# CRF Applications

## CRF Listener
 This example implements a very simple CRF listener application which receives CRF packets from the network and recovers media clock. Additionally, it operates as AAF listener or AAF talker according to the operation mode option passed via command-line argument.

When operating as AAF talker, it sends dummy AAF packets with presentation time that align with the reference clock. AAF packets are sent only after the first CRF packet is received.

When operating as AAF listener, it receives AAF packets and checks if their presentation time is aligned with the clock reference provided by the CRF stream.

Note that the application running on AAF listener mode should be started before the application running on AAF talker mode so the former is able to
recover the media clock and check for AAF stream alignment.

TSN stream parameters (e.g. destination mac address and mode) are passed via command-line arguments. Run 'crf-listener --help' for more information.

This example relies on the system clock to keep the transmission interval when operating in AAF talker mode. So make sure the system clock is synchronized with PTP time. For further information on how to synchronize those clocks see ptp4l(8) and phc2sys(8) man pages. Additionally, make sure you have configured FQTSS feature from your NIC according (for further information see tc-cbs(8)).

Below we provide an example to setup ptp4l, phc2sys and to configure the qdiscs to transmit an AAF stream with 48 kHz sampling rate, 16-bit
sample size, stereo.

On PTP slave host: Replace $IFNAME by your PTP capable NIC name. The gPTP.cfg file mentioned below can be found in /usr/share/doc/linuxptp/
(depending on your distro).

```
$ ptp4l -f gPTP.cfg -i $IFNAME -s
$ phc2sys -f gPTP.cfg -a -r
```

Configure mpqrio (replace $HANDLE_ID by an unused handle ID):

```
$ tc qdisc add dev $IFNAME parent root handle $HANDLE_ID mqprio \
            num_tc 3 map 2 2 1 0 2 2 2 2 2 2 2 2 2 2 2 2 \
            queues 1@0 1@1 2@2 hw 0
```

Configure cbs:

```
$ tc qdisc replace dev $IFNAME parent $HANDLE_ID:1 cbs idleslope 5760 \
            sendslope -994240 hicredit 9 locredit -89 offload 1
```
Finally, the AAF listener mode implemented by this example application is limited and doesn't work with multiple AAF talkers.

## CRF Talker
This example implements a very simple CRF talker application which reads system clock to get current time, generates CRF timestamps, creates AVTP CRF packets and transmit them via the network.

TSN stream parameters (e.g. destination mac address and maximum transit time) are passed via command-line arguments. Run 'crf-talker --help' for more information.

This example relies on system clock to generate CRF timestamps and to keep transmission rate. So make sure the system clock is synchronized with the PTP Hardware Clock (PHC) from your NIC and that the PHC is synchronized with the PTP time from the network. For further information on how to synchronize those clocks see ptp4l(8) and phc2sys(8) man pages.

Here is an example to setup ptp4l and phc2sys on PTP master host. Replace $IFNAME by your PTP capable NIC name. The gPTP.cfg file mentioned below can be found in /usr/share/doc/linuxptp/ (depending on your distro).
```
$ ptp4l -f gPTP.cfg -i $IFNAME
$ phc2sys -f gPTP.cfg -c $IFNAME -s CLOCK_REALTIME -w
 ```
