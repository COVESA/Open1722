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
 *    * Neither the name of COVESA nor the names of its contributors may be 
 *      used to endorse or promote products derived from this software without
 *      specific prior written permission.
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

/**
 * @file
 * This file contains the parser for reading and writing data fields within IEEE
 * 1722 AVTP common header and performs all the necessary conversion from/to host/network
 * byte-order.
 */

#pragma once

#include "avtp/Defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVTP_COMMON_HEADER_LEN             (1 * AVTP_QUADLET_SIZE)

typedef struct {
    uint8_t header[AVTP_COMMON_HEADER_LEN];
    uint8_t payload[0];
} Avtp_CommonHeader_t;

/**
 * Enumeration over all IEEE 1722 header fields. The naming convention used is
 * AVTP_<MSG_TYPE>_FIELD_<FIELD_NAME>.
 */
typedef enum Avtp_CommonHeaderField{
    /* Common AVTP header fields */
    AVTP_COMMON_HEADER_FIELD_SUBTYPE = 0,
    AVTP_COMMON_HEADER_FIELD_H,
    AVTP_COMMON_HEADER_FIELD_VERSION,

    /* Count number of fields for bound checks */
    AVTP_COMMON_HEADER_FIELD_MAX
} Avtp_CommonHeaderField_t;

typedef enum {
    AVTP_SUBTYPE_61883_IIDC        = 0x0,
    AVTP_SUBTYPE_MMA_STREAM        = 0x1,
    AVTP_SUBTYPE_AAF               = 0x2,
    AVTP_SUBTYPE_CVF               = 0x3,
    AVTP_SUBTYPE_CRF               = 0x4,
    AVTP_SUBTYPE_TSCF              = 0x5,
    AVTP_SUBTYPE_SVF               = 0x6,
    AVTP_SUBTYPE_RVF               = 0x7,
    AVTP_SUBTYPE_AEF_CONTINUOUS    = 0x6E,
    AVTP_SUBTYPE_VSF_STREAM        = 0x6F,
    AVTP_SUBTYPE_EF_STREAM         = 0x7F,
    AVTP_SUBTYPE_NTSCF             = 0x82,
    AVTP_SUBTYPE_ESCF              = 0xEC,
    AVTP_SUBTYPE_EECF              = 0xED,
    AVTP_SUBTYPE_AEF_DISCRETE      = 0xEE,
    AVTP_SUBTYPE_ADP               = 0xFA,
    AVTP_SUBTYPE_AECP              = 0xFB,
    AVTP_SUBTYPE_ACMP              = 0xFC,
    AVTP_SUBTYPE_MAAP              = 0xFE,
    AVTP_SUBTYPE_EF_CONTROL        = 0xFF,
} Avtp_AvtpSubtype_t;

/**
 * Returns the value of an an AVTP common header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @returns This function the value of the specified PDU field
 */
uint64_t Avtp_CommonHeader_GetField(const Avtp_CommonHeader_t* const pdu, Avtp_CommonHeaderField_t field);

/**
 * Returns the subtype field of the AVTP common header.
 */
uint8_t Avtp_CommonHeader_GetSubtype(const Avtp_CommonHeader_t* const pdu);

/**
 * Returns the header specific field of the AVTP common header.
 */
uint8_t Avtp_CommonHeader_GetH(const Avtp_CommonHeader_t* const pdu);

/**
 * Returns the version field of the AVTP common header.
 */
uint8_t Avtp_CommonHeader_GetVersion(const Avtp_CommonHeader_t* const pdu);

/**
 * Sets the value of an an AVTP common header field as specified in the IEEE 1722 Specification.
 *
 * @param pdu Pointer to the first bit of an 1722 AVTP PDU.
 * @param field Specifies the position of the data field to be read
 * @param value Pointer to location to store the value.
 */
void Avtp_CommonHeader_SetField(Avtp_CommonHeader_t* pdu, Avtp_CommonHeaderField_t field, uint64_t value);

/**
 * Set the subtype field of the AVTP common header.
 */
void Avtp_CommonHeader_SetSubtype(Avtp_CommonHeader_t* pdu, uint8_t value);

/**
 * Set the header specific field of the AVTP common header.
 */
void Avtp_CommonHeader_SetH(Avtp_CommonHeader_t* pdu, uint8_t value);

/**
 * Set the version field of the AVTP common header.
 */
void Avtp_CommonHeader_SetVersion(Avtp_CommonHeader_t* pdu, uint8_t value);

/******************************************************************************
 * Legacy API (deprecated)
 *****************************************************************************/

struct avtp_common_pdu {
    uint32_t subtype_data;
    uint8_t pdu_specific[0];
} __attribute__ ((__packed__));

struct avtp_stream_pdu {
    uint32_t subtype_data;
    uint64_t stream_id;
    uint32_t avtp_time;
    uint32_t format_specific;
    uint32_t packet_info;
    uint8_t avtp_payload[0];
} __attribute__ ((__packed__));

#define AVTP_FIELD_SUBTYPE      (AVTP_COMMON_HEADER_FIELD_SUBTYPE)
#define AVTP_FIELD_VERSION      (AVTP_COMMON_HEADER_FIELD_VERSION)
#define AVTP_FIELD_MAX          (AVTP_COMMON_HEADER_FIELD_MAX)

/* Get value from Common AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be retrieved.
 * @val: Pointer to variable which the retrieved value should be saved.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_pdu_get(const struct avtp_common_pdu * const pdu, Avtp_CommonHeaderField_t field,
                                uint32_t *val);

/* Set value from Common AVTPDU field.
 * @pdu: Pointer to PDU struct.
 * @field: PDU field to be set.
 * @val: Value to be set.
 *
 * Returns:
 *    0: Success.
 *    -EINVAL: If any argument is invalid.
 */
int avtp_pdu_set(struct avtp_common_pdu *pdu, Avtp_CommonHeaderField_t field,
                                uint32_t val);

#ifdef __cplusplus
}
#endif
