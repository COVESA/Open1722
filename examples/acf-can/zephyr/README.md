# Open1722 for Zephyr Applications

Open1722 libraries being written in C can be compiled easily into Zephyr applications. An example here is the [acf-can-bridge.](acf-can-bridge.c). A brief explanation of how to create Zephyr applications including Open1722 is as follows:

## Installation of the Zephyr Toolchain
Install the Zephyr SDK and toolchain as mentioned in their [Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html).

The acf-can-bridge application is made as a freestanding application, i.e., it is located outside the Zephyr workspace. For more information on such applications, refer [Zephyr build system](https://docs.zephyrproject.org/latest/develop/application/index.html#zephyr-freestanding-app).

## Building _acf-can-bridge_ for Zephyr
To build freestanding Zephyr applications, refer the [blog article](https://www.zephyrproject.org/how-to-build-your-zephyr-app-in-a-standalone-folder/).

For this, we will source the Zephyr dependencies in the terminal:
```
$ source ~/zephyrproject/.venv/bin/activate
$ source ~/zephyrproject/zephyr/zephyr-env.sh
```

Subsequently, you can build the application using _west_. We have integrated the build dependencies of the acf-can-bridge application into the main CMake of the project. Hence build commands are executed from the main folder of the repository.
```
$ west build --pristine -b <board_name> . -- -DCONF_FILE=./examples/acf-can/zephyr/prj.conf -DOPEN1722_ZEPHYR_APP=acf-can-bridge -DDTC_OVERLAY_FILE=<overlay file if reqd.>
$ west build -t run # OR west build -t flash
```

The parameters of the application (e.g. use UDP or the TSCF format) can be set from the [prj.conf.](prj.conf)

In theory, this should work with any supported Zephyr boards having a CAN and an Ethernet interface. You may need to adjust the name of the interface in the corresponding device tree or code. We have tested the application with following Zephyr boards.
- native_sim (Use overlay file: [native_sim.overlay](./boards/native_sim.overlay))
- arduino_portenta_h7 (Use overlay file: [arduino_portenta_ht.overlay](./boards/arduino_portenta_h7.overlay)

## Testing on native_sim
To test on native sim, we first create an Ethernet interface and a CAN inzterface for the sim.

For creation of an Ethernet interface, have a look at the [net-tools repository from zephyrproject.](https://github.com/zephyrproject-rtos/net-tools) Clone this repository and execute the net-setup script in another terminal.
```
$ ./net-setup.sh
```
This creates the zeth Ethernet interface. You must also create a virtual CAN interface based on the devicetree (_zcan_) of the native_sim.

With a virtual Ethernet and CAN interface, the application can be executed on native_sim as follows:
```
$ west build -t run # OR west build -t flash
```

For testing, one can use can-utils to generate traffic on _zcan_ and observe the Ethernet packets on _zeth_ and vice-versa.