![Status - Incubating](https://img.shields.io/static/v1?label=Status&message=Incubating&color=FEFF3A&style=for-the-badge)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/COVESA/Open1722/build-all.yml?branch=main&style=for-the-badge)



<a name="readme-top"></a>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/COVESA/Open1722">
    <img src="./logo/open1722logo.png" alt="Open1722 logo" width="400px">
  </a>

<h2 align="center">Covesa Open1722</h2>

  <p align="center">
    Open1722  is an implementation of the IEEE 1722 protocol, for streaming audio/video, tunneling CAN/LIN messages and enabling remote access to peripheral bus systems.
    <br />
    <br />
    <a href="https://github.com/COVESA/Open1722/issues">Report Bug</a>
    ·
    <a href="https://github.com/COVESA/Open1722/issues">Request Feature</a>
    </p>
</div>


### Maintainers

* [Naresh Nayak - Robert Bosch GmbH](https://github.com/nayakned)
* [Adriaan Niess - Robert Bosch GmbH](https://github.com/adriaan-niess)
* [Kamel Fakih - Robert Bosch GmbH](https://github.com/kamelfakihh/)

## Introduction

Open1722 is a fork of [AVNU/libavtp](https://github.com/Avnu/libavtp) which is an open source reference implementation of the Audio Video Transport Protocol (AVTP) specified in IEEE 1722-2016 spec. _libavtp_ primarily focuses on audio video data formats of the IEEE 1722-2016 spec.

IEEE 1722 is also gaining a lot of traction in the automotive community, mainly, to bridge fieldbus technologies over automotive Ethernet. In particular the AVTP Control Formats (ACF) specify serialization for a set of data formats relevant for automotive applications (e.g., CAN, LIN, etc.). Open1722 extends/modifies _libavtp_ to also include these ACF formats.

NOTE: Open1722 is currently incubating and under active development. The APIs are not fully stable and are subject to changes.

Open1722 is under BSD License. For more information see LICENSE file.

## Implementation

This repository is organized as follows:
- The `src/` and `include/` folders contain the IEEE 1722 protocol implementation. We strive to make the implementation platform independant and avoid usage of platform specific headers or libraries. For now the implementation is tested only on Linux.
- The `examples/` folder contains various applications that use our Open1722 library. Most applications are targeted to Linux platforms. Few applications (e.g. [_acf-can-bridge_](./examples/acf-can/zephyr/)) are also ported for Zephyr RTOS. Compilation instructions for Zephyr is available in the corresponding folder of the application.

Before building Open1722 make sure you have installed the following software :
* CMake >= 3.20
* CMocka >= 1.1.0 (For running unit tests. This can be installed on Debian/Ubuntu using ```sudo apt install libcmocka-dev```)

Alternatively, you can use VS Code to run the provided dev container which takes care of the dependencies.

The first step to build Open1722 is to generate the Makefile and build the project.
```
$ mkdir build
$ cd build
$ cmake ..
$ make
```
This builds the libraries _libopen1722_ containing all the data formats specified in the IEEE 1722-2016 specification along with _libopen1722custom_ which contains customized serialization formats which can be sent over IEEE 1722.

To execute available unit tests:
```
$ cmake ..
$ make unittests
$ make test
```

The [examples](./examples/) can be built as follows:
```
$ make examples
```

The build can be cleaned using the following command:
```
$ make clean
```

To install Open1722 on your system run:
```
$ sudo make install
```

To cross-compile for aarch64 (e.g. Raspberry Pi), you can use the [toolchain file](./aarch64.toolchain) we provided. Note that this requires a fresh build process with a new ```build``` folder.
```
$ sudo apt install gcc-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu
$ cmake .. -DCMAKE_TOOLCHAIN_FILE=../aarch64.toolchain
$ make
```

You can also find a toolchain file for ARM-Cortex-M [here](./arm-cortex-m.toolchain).

## AVTP Formats Support

AVTP protocol defines several AVTPDU type formats (see Table 6 from IEEE 1722-2016 spec).

The following is the list of the formats currently supported by Open1722:
 - AAF (PCM encapsulation only)
 - CRF
 - CVF (H.264, MJPEG, JPEG2000)
 - RVF
 - AVTP Control Formats (ACF) with Non-Time-Synchronous as well as Time-Synchronous formats (see Table 22 from IEEE 1722-2016 spec)
    - CAN
    - CAN Brief
    - Flexray
    - LIN
    - MOST
    - GPC
    - Sensor
    - Sensor Brief
  - Custom formats not included in the standard but can be transported on top of IEEE 1722
    - COVESA Vehicle Signal Specification (VSS) [(Protocol description)](./examples/acf-vss/protocol_description/acf-vss.md)

## Examples

The `examples/` directory provides sample applications which demonstrate the Open1722 functionalities. Each example directory contains a README file that includes specific details on its functionality, configuration, and dependencies.

To execute the IEEE 1722 CAN Talker application:
```
$ ./build/examples/acf-can/linux/acf-can-talker
```

### Programming Tutorial

Here's a small example how the Open1722 library can be used to build and parse IEEE 1722 Protocol Data Units (aka PDUs). First define a C struct for a custom IEEE 1722 packet that can be used to transport a CAN and a LIN message. The frame begins with a Time-synchronous Control Format (TSCF) header. Alternatively a Non-Timesynchronous Control Format (NTSCF) header could be used. After the TSCF header a list of AVTP Control Format (ACF) messages follows. The first ACF message is a ACF CAN message which consists of ACF CAN header as well as a payload section to carry a 2Byte CAN frame. Similar than with the CAN message another ACF messages for LIN is added.

``` C
// my_1722_pdu.h

#include "avtp/Udp.h"
#include "avtp/acf/Tscf.h"
#include "avtp/acf/Can.h"
#include "avtp/acf/Lin.h"

#define CAN_PAYLOAD_LEN 2
#define LIN_PAYLOAD_LEN 3

typedef struct {
    // IEEE 1722 UDP encapsulation header (optional)
    Avtp_Udp_t udp;
    // IEEE 1722 TSCF header
    Avtp_Tscf_t tscf;
    // IEEE 1722 ACF message #1
    Avtp_Can_t can;
    uint8_t canPayload[CAN_PAYLOAD_LEN];
    // IEEE 1722 ACF message #2
    Avtp_Lin_t lin;
    uint8_t linPayload[LIN_PAYLOAD_LEN];
} My1722Pdu_t;
```

In the next step we're going to c

``` C
// talker.h

#include "my_1722_pdu.h"

int main()
{
    My1722Pdu_t pdu;

    // Init UDP encapsulation header
    Avtp_Udp_Init(&pdu.udp);

    // Init TSCF header
    Avtp_Tscf_Init(&pdu.tscf);
    Avtp_Tscf_SetVersion(&pdu.tscf, 0);
    Avtp_Tscf_SetSequenceNum(&pdu.tscf, 123);
    Avtp_Tscf_SetStreamId(&pdu.tscf, 0xAABBCCDDEEFF);
    Avtp_Tscf_SetTv(&pdu.tscf, 1);
    Avtp_Tscf_SetAvtpTimestamp(&pdu.tscf, 0x11223344);

    // Init CAN ACF message
    Avtp_Can_Init(&pdu.can);
    Avtp_Can_SetCanBusId(&pdu.can, 4);
    uint8_t canFrame[CAN_PAYLOAD_LEN] = {0x11, 0x22};
    memcpy(pdu.can.payload, canFrame, CAN_PAYLOAD_LEN);

    // Init LIN ACF message
    Avtp_Lin_Init(&pdu.lin);
    uint8_t linFrame[LIN_PAYLOAD_LEN] = {0x11, 0x22, 0x33};
    memcpy(pdu.lin.payload, linFrame, LIN_PAYLOAD_LEN);

    // Send packet to network using socket API ...
    uint8_t* data = &pdu;
    size_t dataLen = sizeof(My1722Pdu_t);
    // int socket = ...
    // sendto(socket, data, dataLen, 0);
}
```

## Contribute to Open1722

For detailed information see our [contribution guide](./CONTRIBUTING.md)!