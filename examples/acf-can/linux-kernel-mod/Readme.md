# ACF CAN kernel module

> [!CAUTION]
> Open1722 is in active development. This kernel module is a fun experiment on top of that. Note that kernel modules can crash your computer in fun and unexpected ways _anytime_.

This is an experiment to wrap Open1722 ACF-CAN functionality in a Linux CAN kernel module. That means your applications can use the normal Linux socketcan interface (like using hw CAN interfaces or vcan), but will speak ACF-CAN via Ethernet directly.


## Notes on compilation

Make sure you are generally setup to compile kernel modules, e.g.

```
sudo apt update && sudo apt upgrade
sudo apt-get install gcc make build-essential libncurses-dev exuberant-ctags build-essential linux-headers-`uname -r
```

Then in this folder do

```
export CONFIG_ACF_CAN=m
make
```

## Building failed
Likely building fails for you with a message like

```
ERROR: modpost: GPL-incompatible module acfcan.ko uses GPL-only symbol 'skb_tstamp_tx'
```
The reason is, currently we are only able to release BSD licensed ode in this repo, however in the kernel we need to use interfaces that are only allowed to be used from GPL-licensed code. Luckily YOU are free to use BSD code in GPL context on your computer. So take a look at `MODULE_LICENSE` in  [./acfcanmodulemetadata.h]()./acfcanmodulemetadata.h). Hint: `Dual BSD/GPL`

## Loading

If you load the module the first time from a local folder, and your kernel has not yet loaded anything form the CAN subsystem you will get missing symbols. Easy fix, jut load `vcan` module via mpdprobe, whoch will make sure all necessary dependenecies are pulled into into the kernel

```
sudo modprobbe vcan
```

Afterwards load module with

```
sudo insmod acfcan.ko 
``` 

## Using
You can add a number of acfcan interfaces. Some aspects like destination MAC or ethernet infterface to be used need to be configured via sysfs _after_ the interface is created, but _before_ it is set to up.

See this for a short example

```
sudo ip link add dev acfcan0 type acfcan
sudo ip link set acfcan0 mtu 16
sudo echo -n "eth0"  | sudo tee /sys/class/net/acfcan0/acfcan/ethif
sudo ip link set up acfcan0
```

watch kernel log via `dmesg --follow` to see any any warnings.
