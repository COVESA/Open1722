# ACF-CAN Applications

Following applications are available in this folder:
- _acf-can-listener_: Parses received IEEE 1722 ACF frames and puts our the encapsulated CAN/CAN-FD frames onto the CAN bus
- _acf-can-talker_: Creates IEEE 1722 ACF frames out of received CAN frames and sends them out on the network interface
- _acf-can-bridge_: Combines the _acf-can-talker_ and _acf-can-listener_ to create a two way bridge between a CAN interface and an Ethernet network interface

All these applications support IEEE 1722 over Ethernet (layer 2) as well as over UDP (layer 4).
These applications can be used along with Linux CAN utilities. On Ubuntu/Debian Linux distributions, these utilities can be installed using the package manager `apt install can-utils`

## acf-can-talker
_acf-can-talker_ receives frames on a (virtual) CAN interface and sends out the corresponding IEEE 1722 ACF messages. The parameters for its usage are as follows:

```
Usage: acf-can-talker [OPTION...]

acf-can-talker -- a program to send CAN messages to a remote CAN bus over
Ethernet using Open1722.

      --canif=CAN_IF         CAN interface
  -c, --count=COUNT          Set count of CAN messages per Ethernet frame
  -d, --dst-addr=MACADDR     Stream destination MAC address (If Ethernet)
      --fd                   Use CAN-FD
  -i, --ifname=IFNAME        Network interface (If Ethernet)
  -n, --dst-nw-addr=NW_ADDR  Stream destination network address and port (If
                             UDP)
      --stream-id=STREAM_ID  Stream ID for talker stream
  -t, --tscf                 Use TSCF (Default: NTSCF)
  -u, --udp                  Use UDP (Default: Ethernet)
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

## acf-can-talker
_acf-can-listener_ receives IEEE 1722 ACF messages and puts out the corresponding CAN frames on a (virtual) CAN interface. The parameters for its usage are as follows:

```
Usage: acf-can-listener [OPTION...]

acf-can-listener -- a program designed to receive CAN messages from a remote
CAN bus over Ethernet using Open1722.

      --canif=CAN_IF         CAN interface
  -d, --dst-addr=MACADDR     Stream destination MAC address (If Ethernet)
      --fd                   Use CAN-FD
  -i, --ifname=IFNAME        Network interface (If Ethernet)
  -p, --udp-port=UDP_PORT    UDP Port to listen on (if UDP)
      --stream-id=STREAM_ID  Stream ID for listener stream
  -u, --udp                  Use UDP (Default: Ethernet)
  -?, --help                 Give this help list
      --usage                Give a short usage message

```

## acf-can-bridge
_acf-can-bridge_ bridges the Ethernet domain with the CAN domain, i.e., all received IEEE 1722 ACF frames will be parsed for extracting CAN frames which will be sent out on CAN bus and all received CAN frames will be packed into IEEE 1722 ACF messages and sent out on the Ethernet interface.

```
acf-can-bridge -- a program designed to receive CAN messages from a remote CAN
bus over Ethernet using Open1722.

      --canif=CAN_IF         CAN interface
  -c, --count=COUNT          Set count of CAN messages per Ethernet frame
  -d, --dst-addr=MACADDR     Stream destination MAC address (If Ethernet)
      --fd                   Use CAN-FD
  -i, --ifname=IFNAME        Network interface (If Ethernet)
      --listener-stream-id=STREAM_ID
                             Stream ID for listener stream
  -n, --dst-nw-addr=NW_ADDR  Stream destination network address and port (If
                             UDP)
  -p, --udp-port=UDP_PORT    UDP Port to listen on (if UDP)
      --talker-stream-id=STREAM_ID
                             Stream ID for talker stream
  -t, --tscf                 Use TSCF
  -u, --udp                  Use UDP
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

## Quickstart Tutorials
### 1. Tunneling CAN over IEEE 1722 using Linux CAN utilities
Here is an example of how CAN frames can be tunneled over an Ethernet link using _acf-can-talker_ and _acf-can-listener_.

```
vcan0 -> acf-can-talker -> Ethernet/UDP -> acf-can-listener -> vcan1
```

We use two virtual CAN interfaces, _vcan0_ and _vcan1_, which can be setup using following commands:
```
$ modprobe vcan
$ ip link add dev vcan0 type vcan   # Execute these commands also for vcan1
$ ip link set dev vcan0 up
```

#### Generate CAN traffic
On Terminal 1, generate CAN traffic for vcan0:
```
$ cangen vcan0
```

In the following, we tunnel this generated CAN traffic over Ethernet to _vcan1_

#### Use Talker Application for tunneling
On Terminal 2, pipe generated CAN traffic from vcan0 to _acf-can-talker_. Here, we use UDP encapsulation.
```
$ ./acf-can-talker -u --dst-nw-addr 127.0.0.1:17220 --canif vcan0
```
Alternatively, we can directly use Ethernet for transport.
```
$ ./acf-can-talker --dst-addr aa:bb:cc:dd:ee:ff -i eth0 --canif vcan0
```

#### Use Listener Application for receiving
On Terminal 3, receive the IEEE 1722 traffic using _acf-can-listener_ and put the CAN frame out on vcan1.

If the talker uses UDP encapsulation:
```
$ ./acf-can-listener -u -p 17220 --canif vcan1
```

Alternatively, if Ethernet is directly used:
```
$ ./acf-can-listener --dst-addr aa:bb:cc:dd:ee:ff -i eth0 --canif vcan0
```

#### Receive CAN traffic

You can now compare CAN traffic seen on _vcan0 and vcan1_ to check if the tunneling works.
```
candump vcan0        # use another terminal for vcan1
```
Note that the tunneling works in these examples only in one direction (_vcan0_ -> _vcan1_).

### 2. Bridging Ethernet with CAN

```
vcan0 <-> acf-can-bridge <-> Ethernet/UDP
```

- Create virtual CAN _vcan0_ and generate traffic on it as shown above in Tutorial 1.
- Execute the _acf-can-bridge_
```
$ ./acf-can-bridge --dst-addr aa:bb:cc:dd:ee:ff -i eth0 --canif vcan0
```
- Execute wireshark and capture Ethernet packets on _eth0_.
- (Optional) You could also use the _acf-can-talker_ to generate IEEE 1722 ACF frames on _eth0_, which will then be sent as CAN frames on _vcan0_.


