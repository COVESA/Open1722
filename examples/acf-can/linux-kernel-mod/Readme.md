# ACF CAN kernel module

> [!CAUTION]
> Open1722 is in active development. This kernel module is a fun experiment on top of that. Note that kernel modules can crash your computer in fun and unexpected ways _anytime_.


This wrap Open1722 ACF-CAN functionality in a Linux CAN kernel module. That means your applications can use the normal Linux socketcan interface (like using HW CAN interfaces or vcan), but will speak ACF-CAN via Ethernet directly.
Compared to the [Linux user space examples](../linux) the kernel module leads to less user/kernelspace switches, and you do not need to deal with addtional user space processes. 

## Architecture

With this module, from user space perspective there is no difference between a real CAN device supported by a kernel driver or speaking IEEE 1722 acf-can over any ethernet-like interface supported by the kernel.

![ACF CAN Kernel Architecture](acfcankernel.svg)

## Features

### Supported
 - CAN and CAN FD
 - configurable stream and bus id
 - NTSCF
 - ACF-CAN
 - Sending and receiving

### Not (yet) supported
 - unidirectional operation (RX or TX only)
 - CAN-BRIEF
 - TSCF
 - batching. currently only ONE ACF-CAN message per 1722 frame is allowed


## How to compile

Make sure you are generally setup to compile kernel modules, e.g. in Ubuntu something like

```
sudo apt update && 
sudo apt-get install gcc make build-essential libncurses-dev exuberant-ctags build-essential linux-headers-`uname -r`
```

Then in this folder do

```
export CONFIG_ACF_CAN=m
make
```

## Using the module

### Loading the module

If you load the module the first time from a local folder, and your kernel has not yet loaded anything form the CAN subsystem you will get missing symbols. Easy fix, just load the `can` module via mpdprobe, whoch will make sure all necessary dependenecies are pulled into into the kernel

```
sudo modprobe can
```

Afterwards load module with

```
sudo insmod acfcan.ko
```

### Secure Boot

If you have a secure boot system you may not be able to load unsigned kernel modules. See [https://ubuntu.com/blog/how-to-sign-things-for-secure-boot](https://ubuntu.com/blog/how-to-sign-things-for-secure-boot) for hints to fix that.

### Example

You can add a number of acfcan interfaces. Some aspects like destination MAC or ethernet infterface to be used need to be configured via sysfs _after_ the interface is created, but _before_ it is set to up.

This is a complete example to set up 2 acf-can interfaces connected via two _virtual_ ethernet interfaces on a single machine. 

First set up a pair of virtual ethernet interfaced as in [./instalmon.sh](./installmon.sh):

```sh
ip link add dev mon1 type veth peer name mon2
ip link set dev mon2 up
ip link set dev mon1 up
```

Then we set up the two Open1722 ACF-CAN interfaces as in [./myup.sh](./myup.sh):

```sh
sudo ip link add dev ecu1 type acfcan
sudo ip link add dev ecu2 type acfcan

sudo ip link set ecu1 mtu 72
sudo ip link set ecu2 mtu 72

sudo echo -n "mon1"  | sudo tee /sys/class/net/ecu1/acfcan/ethif
sudo echo -n "mon2"  | sudo tee /sys/class/net/ecu2/acfcan/ethif

sudo echo -n $(cat /sys/class/net/mon2/address)  | sudo tee /sys/class/net/ecu1/acfcan/dstmac
sudo echo -n $(cat /sys/class/net/mon1/address)  | sudo tee /sys/class/net/ecu2/acfcan/dstmac


sudo echo -n "cafe11"  | sudo tee /sys/class/net/ecu1/acfcan/tx_streamid
sudo echo -n "dead22"  | sudo tee /sys/class/net/ecu2/acfcan/tx_streamid

sudo echo -n "dead22"  | sudo tee /sys/class/net/ecu1/acfcan/rx_streamid
sudo echo -n "cafe11"  | sudo tee /sys/class/net/ecu2/acfcan/rx_streamid

sudo ip link set up ecu1
sudo ip link set up ecu2
```

Note that IEEE-1722 specific options for an ACF-CAn device `<devname>` can be set via sysfs in the folder `/sys/class/net/<devname>/acfcan`.
This can only be done when the interface is (still) _down_. You can always change options by downing the interface, changing the desired option and bringing it up again.

Keep an eye out in kernel logs via `dmesg --follow` for any problems. 

once everything is setup you can use `cansend` and `candump` to see every message you sent to ACF-CAN interface `ecu1` being replicated on `ecu2` and vice versa.

With tcpdump or wireshark you can see the IEEE-1722 frames on the `mon1` and  `mon2` interfaces.

To really distribute this on two machines, set up interface `ecu1` on the first machine, using the real ethernet inferface for the `ethif` option and do the same for `ecu2` on the second machine.

## Debugging
If your kernel supports [dynamic debugging](https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html) you can enable debug messages from the kernel module by doing 

```
echo 'module acfcan +p'>  /sys/kernel/debug/dynamic_debug/control
```

after loading it.
