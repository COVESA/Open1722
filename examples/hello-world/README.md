# Hello World!

The hello-world applications provide an exemplary set of listener and talker based on the IEEE 1722 protocol.
These applications are based on the Genereal Purpose Control (GPC) subtype of the AVTP Control Formats.

## hello-world-talker
_hello-world-talker_ sends the string "Hello World!" packed in a GPC frame of AVTP Control Format.
The string being sent can be changed using the ```--message``` option.
Options are available to send the IEEE 1722 frame as layer 2 frame or as a UDP segment.

To run over Ethernet
```
$ ./hello-world-talker --ifname <Ethernet interface name> --dst-addr <Destination MAC address>
```

To run over UDP
```
$ ./hello-world-talker --udp --dst-nw-addr <destination IP>:<Port>
```

You can observe the IEEE1722 frames by running wireshark on the appropriate interface.


## hello-world-listener
_hello-world-listener_ receives the message string sent by the talker and prints it out on the console. The listener shall be operated in the same configuration (e.g. layer 2 or UDP) as the talker to ensure compatability.

To run over Ethernet
```
$ ./hello-world-listener --ifname <Ethernet interface name>
```

To run over UDP
```
$ ./hello-world-talker --udp <--udp-port=<UDP port>
```