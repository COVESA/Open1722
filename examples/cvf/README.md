# CVF Applications

## CVF Listener
This example implements a very simple CVF listener application which receives CVF packets from the network, retrieves video data and writes them to stdout once the presentation time is reached.

For simplicity, this examples accepts only CVF H.264 packets, and the H.264 data must be composed of NAL and each NAL unit can not exceed 1400 bytes.

The H.264 data sent to output is in H.264 byte-stream format.

TSN stream parameters such as destination mac address are passed via command-line arguments. Run 'cvf-listener --help' for more information.

This example relies on the system clock to schedule video data samples for presentation. So make sure the system clock is synchronized with the PTP Hardware Clock (PHC) from your NIC and that the PHC is synchronized with the PTP time from the network. For further information on how to synchronize those clocks see ptp4l(8) and phc2sys(8) man pages.

### Display with GStreamer

The easiest way to use this example is by combining it with a GStreamer pipeline. We use GStreamer to read the H.264 byte-stream from stdin and present it. So, to play an H.264 video from a TSN stream and show it on a X display, you can do something like:

```
$ cvf-listener <args> | gst-launch-1.0 filesrc location=/dev/stdin \
  ! h264parse ! avdec_h264 ! videoconvert ! autovideosink
```

### Recording to a file

The listener writes a raw H.264 byte-stream without any container timing information. `matroskamux`/`mp4mux` cannot be used directly behind it: GStreamer's `h264parse` does not synthesise presentation timestamps for an untimed stream and those muxers drop buffers without a valid timestamp (the resulting file only contains the container header). There are two ways to obtain a file that can be copied off a headless machine and replayed.

**GStreamer (raw H.264).** Redirect the listener output to a `.h264` file. VLC, `ffplay` and the GStreamer decode pipeline above can play such a file directly:

```
$ sudo ./cvf-listener <args> > output.h264
$ gst-launch-1.0 filesrc location=output.h264 ! h264parse ! avdec_h264 \
  ! videoconvert ! autovideosink
```

**ffmpeg (MP4/MKV).** ffmpeg's raw H.264 demuxer generates timestamps from the frame rate, so it can wrap the stream in a common container. The frame rate must match the talker (`videotestsrc` defaults to 30/1):

```
$ sudo ./cvf-listener <args> | ffmpeg -f h264 -framerate 30 -i - -c:v copy output.mp4
```

The same command can remux a previously captured raw file:

```
$ ffmpeg -f h264 -framerate 30 -i output.h264 -c:v copy output.mp4
```

`-c:v copy` avoids re-encoding. If the recording starts in the middle of a GOP (before the first SPS/PPS/IDR has been received), use `-c:v libx264` instead, start the listener before the talker, or use `key-int-max=30` on the talker side (see below).

### Troubleshooting

`Sequence number mismatch: expected X, got Y` messages mean that frames were lost between talker and listener (the listener logs them and continues). The most common cause is a talker pipeline that is not running in real time - see `is-live=true` below.

## CVF Talker
This example implements a very simple CVF talker application which reads an H.264 byte-stream from stdin, creates CVF packets and transmit them via network.

For simplicity, this example supports only NAL units in byte-stream format, and each NAL unit can not exceed 1400 bytes.

TSN stream parameters (e.g. destination mac address, traffic priority) are passed via command-line arguments. Run 'cvf-talker --help' for more information.

In order to have this example working properly, make sure you have configured FQTSS feature from your NIC according (for further information see tc-cbs(8)). Also, this example relies on system clock to set the AVTP timestamp so make sure it is synchronized with the PTP Hardware Clock (PHC) from your NIC and that the PHC is synchronized with the network clock. For further information see ptp4l(8) and phc2sys(8).

The easiest way to use this example is by combining it with a GStreamer pipeline. We use GStreamer to provide an H.264 stream that is sent to stdout, from where this example reads the stream. So, to generate an H.264 video to send via TSN network, you can do something like:

```
$ gst-launch-1.0 -e -q videotestsrc pattern=ball is-live=true \
  ! video/x-raw,width=192,height=144 ! x264enc key-int-max=30 \
  ! video/x-h264,stream-format=byte-stream ! filesink location=/dev/stdout \
  | cvf-talker <args>
```

Note that the `x264enc` may be changed by any other H.264 encoder available, as long as it generates a byte-stream with NAL units no longer than 1400 bytes.

`is-live=true` makes `videotestsrc` produce frames at the configured frame rate instead of as fast as the CPU allows; without it the talker floods the receiver and the listener drops frames. `key-int-max=30` inserts a key frame (with SPS/PPS) roughly once per second, so listeners and recordings that start mid-stream can decode from the next key frame.
