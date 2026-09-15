# ACF-VSS

The two applications available in this folder are acf-vss-listener and acf-vss-talker. Together they can be used as sample applications for implementing the (de-)serialization of VSS on IEEE 1722 as described in [Protocol description](./protocol_description/acf-vss.md).

## ACF-VSS-Talker
This application sends Vehicle.Speed as a float value.
To run this application using UDP:
```
$ ./acf-vss-talker -u 10.0.0.2:17220
```

For using Ethernet layer as a transport:
```
$ ./acf-vss-talker <interface name> <Destination MAC Address>
```

## ACF-VSS-Listener
This application receives the VSS values sent by ACF-VSS-Talker application.
To receive the VSS messages over IEEE 1722 using UDP.
```
$ ./acf-vss-listener -u -p 17220
```

For receiving VSS messages over Ethernet layer as a transport:
```
$ ./acf-vss-listener <interface_name> <Destination MAC Address>
```
