# AAF Applications

## AAF Listener
This example implements a very simple AAF listener application which receives AAF packets from the network, retrieves the PCM samples, and writes them to stdout once the presentation time is reached.

For simplicity, the example only accepts AAF packets with the following specification:
- Sample format: 16-bit little endian
- Sample rate: 48 kHz
- Number of channels: 2 (stereo)

TSN stream parameters such as destination mac address are passed via command-line arguments. Run 'aaf-listener --help' for more information.

This example relies on the system clock to schedule PCM samples for playback. So make sure the system clock is synchronized with the PTP Hardware Clock (PHC) from your NIC and that the PHC is synchronized with the PTP time from the network. For further information on how to synchronize those clocks see ptp4l(8) and phc2sys(8) man pages.

The easiest way to use this example is combining it with 'aplay' tool provided by alsa-utils. 'aplay' reads a PCM stream from stdin and sends it to a ALSA playback device (e.g. your speaker). So, to play Audio from a TSN stream, you should do something like this:
```
$ aaf-listener <args> | aplay -f dat -t raw -D <playback-device>
```
## AAF Talker
This example implements a very simple AAF talker application which reads a PCM stream from stdin, creates AAF packets and transmit them via the network.

For simplicity, the example supports only one set of PCM parameters:
 - Sample format: 16-bit little endian
 - Sample rate: 48 kHz
 - Number of channels: 2 (stereo)

TSN stream parameters (e.g. destination mac address, traffic priority) are passed via command-line arguments. Run 'aaf-talker --help' for more information.

In order to have this example working properly, make sure you have configured FQTSS feature from your NIC according (for further information see tc-cbs(8)). Also, this example relies on system clock to set the AVTP timestamp so make sure it is synchronized with the PTP Hardware Clock (PHC) from your NIC and that the PHC is synchronized with the network clock. For further information see ptp4l(8) and phc2sys(8).

The easiest way to use this example is combining it with 'arecord' tool provided by alsa-utils. 'arecord' reads the PCM stream from a capture ALSA device (e.g. your microphone) and writes it to stdout. So to stream Audio captured from your mic to a TSN network you should do something like this:

```
$ arecord -f dat -t raw -D <capture-device> | aaf-talker <args>
```
