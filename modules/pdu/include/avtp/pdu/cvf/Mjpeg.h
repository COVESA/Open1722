/*
 * Copyright (c) 2024, COVESA
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of COVESA, Intel Corporation nor the names of its
 *      contributors  may be used to endorse or promote products derived from 
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <stdint.h>

#include "avtp/pdu/Utils.h"

#define AVTP_MJPEG_HEADER_LEN (2 * AVTP_QUADLET_SIZE)

typedef struct Avtp_Mjpeg {
    uint8_t header[AVTP_MJPEG_HEADER_LEN];
    uint8_t payload[0];
} Avtp_Mjpeg_t;

typedef enum Avtp_MjpegField {
    /* MJPEG header fields */
    AVTP_MJPEG_FIELD_TYPE_SPECIFIC,
    AVTP_MJPEG_FIELD_FRAGMENT_OFFSET,
    AVTP_MJPEG_FIELD_TYPE,
    AVTP_MJPEG_FIELD_Q,
    AVTP_MJPEG_FIELD_WIDTH,
    AVTP_MJPEG_FIELD_HEIGHT,
    /* Count number of fields for bound checks */
    AVTP_MJPEG_FIELD_MAX
} Avtp_MjpegField_t;

int Avtp_Mjpeg_Init(Avtp_Mjpeg_t* pdu);

int Avtp_Mjpeg_GetField(Avtp_Mjpeg_t* pdu, Avtp_MjpegField_t field, uint64_t* value);

int Avtp_Mjpeg_SetField(Avtp_Mjpeg_t* pdu, Avtp_MjpegField_t field, uint64_t value);
