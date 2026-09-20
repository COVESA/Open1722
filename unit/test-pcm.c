/*
 * Copyright (c) 2026, COVESA
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#if defined(__cplusplus)
extern "C" {
#include <cmocka.h>
}
#else
#include <cmocka.h>
#endif
#include <arpa/inet.h>
#include <string.h>

#include "avtp/CommonHeader.h"
#include "avtp/CommonStreamHeader.h"
#include "avtp/aaf/Aaf.h"
#include "avtp/aaf/Pcm.h"

#define MAX_PDU_SIZE 1500

static uint32_t read_quadlet(const uint8_t *pdu, size_t quadlet)
{
    uint32_t word;

    memcpy(&word, pdu + (quadlet * 4), sizeof(word));
    return ntohl(word);
}

static uint64_t mask_field_value(uint8_t bits, uint64_t value)
{
    if (bits == 0) {
        return 0;
    }
    if (bits >= 64) {
        return value;
    }
    return value & ((((uint64_t)1) << bits) - 1);
}

/* Initializes a minimal but valid AAF PCM frame. */
static void init_valid_pcm(Avtp_Pcm_t *pdu)
{
    Avtp_Pcm_Init(pdu);
    Avtp_Pcm_SetChannelsPerFrame(pdu, 2);
    Avtp_Pcm_SetBitDepth(pdu, 16);
}

static void pcm_init(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_PCM_HEADER_LEN_V0];

    assert_int_equal(sizeof(Avtp_Pcm_t), AVTP_PCM_HEADER_LEN_V0);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Pcm_Init(NULL);

    Avtp_Pcm_Init((Avtp_Pcm_t *)pdu);
    memset(init_pdu, 0, AVTP_PCM_HEADER_LEN_V0);
    init_pdu[0] = AVTP_SUBTYPE_AAF; /* subtype = AAF */
    init_pdu[1] = 0x80;             /* sv = 1, version = 0 */
    assert_memory_equal(init_pdu, pdu, AVTP_PCM_HEADER_LEN_V0);
}

static void pcm_init_v1(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t init_pdu[AVTP_PCM_HEADER_LEN_V1];

    assert_int_equal(sizeof(Avtp_PcmV1_t), AVTP_PCM_HEADER_LEN_V1);

    /* Passing a NULL pointer must be a no-op. */
    Avtp_Pcm_InitV1(NULL);

    Avtp_Pcm_InitV1((Avtp_PcmV1_t *)pdu);
    memset(init_pdu, 0, AVTP_PCM_HEADER_LEN_V1);
    init_pdu[0] = AVTP_SUBTYPE_AAF; /* subtype = AAF */
    init_pdu[1] = 0x90;             /* sv = 1, version = 1 */
    assert_memory_equal(init_pdu, pdu, AVTP_PCM_HEADER_LEN_V1);

    assert_int_equal(Avtp_Pcm_GetHeaderLen((Avtp_Pcm_t *)pdu), AVTP_PCM_HEADER_LEN_V1);
}

static void pcm_is_valid(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    init_valid_pcm(pcm);
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* NULL pdu. */
    assert_false(Avtp_Pcm_IsValid(NULL, MAX_PDU_SIZE));

    /* Not an AAF frame. */
    memset(pdu, 0, MAX_PDU_SIZE);
    assert_false(Avtp_Pcm_IsValid(pcm, MAX_PDU_SIZE));

    /* Buffer smaller than the AAF header. */
    init_valid_pcm(pcm);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0 - 1));

    /* stream_data_length does not fit into the buffer. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetStreamDataLength(pcm, 10);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0 + 9));
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0 + 10));

    /* AES3 (0x05) and reserved format values (0x06) are not PCM. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_AES3_32BIT);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));
    Avtp_Pcm_SetFormat(pcm, (Avtp_AafFormat_t)0x06);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* channels_per_frame shall be a positive integer. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetChannelsPerFrame(pcm, 0);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* bit_depth shall not be zero. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetBitDepth(pcm, 0);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* bit_depth shall not exceed the sample container size. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_INT_16BIT);
    Avtp_Pcm_SetBitDepth(pcm, 24);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));
    Avtp_Pcm_SetBitDepth(pcm, 16);
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    init_valid_pcm(pcm);
    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_INT_24BIT);
    Avtp_Pcm_SetBitDepth(pcm, 24);
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));
    Avtp_Pcm_SetBitDepth(pcm, 32);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    init_valid_pcm(pcm);
    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_INT_32BIT);
    Avtp_Pcm_SetBitDepth(pcm, 32);
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* FLOAT_32BIT requires bit_depth to be exactly 32. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_FLOAT_32BIT);
    Avtp_Pcm_SetBitDepth(pcm, 24);
    assert_false(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));
    Avtp_Pcm_SetBitDepth(pcm, 32);
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* The sample size of a user format is not constrained. */
    init_valid_pcm(pcm);
    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_USER);
    Avtp_Pcm_SetBitDepth(pcm, 20);
    assert_true(Avtp_Pcm_IsValid(pcm, AVTP_PCM_HEADER_LEN_V0));

    /* Valid version 1 frame. */
    Avtp_Pcm_InitV1((Avtp_PcmV1_t *)pdu);
    Avtp_Pcm_SetChannelsPerFrame((Avtp_Pcm_t *)pdu, 2);
    Avtp_Pcm_SetBitDepth((Avtp_Pcm_t *)pdu, 16);
    assert_true(Avtp_Pcm_IsValid((Avtp_Pcm_t *)pdu, AVTP_PCM_HEADER_LEN_V1));
    assert_false(Avtp_Pcm_IsValid((Avtp_Pcm_t *)pdu, AVTP_PCM_HEADER_LEN_V1 - 1));

    /* Unsupported version is rejected. */
    init_valid_pcm(pcm);
    Avtp_CommonHeader_SetVersion((Avtp_CommonHeader_t *)pdu, 2);
    assert_false(Avtp_Pcm_IsValid(pcm, MAX_PDU_SIZE));
}

static void mark_descriptors(uint8_t *coverage, size_t coverageBits,
                             const Avtp_FieldDescriptor_t *desc, uint8_t numFields)
{
    for (uint8_t i = 0; i < numFields; i++) {
        uint8_t bits = desc[i].bits;
        uint8_t offset = desc[i].offset;
        uint8_t quadlet = desc[i].quadlet;

        for (uint8_t b = 0; b < bits; b++) {
            size_t bit = ((size_t)quadlet * 32) + offset + b;

            assert_true(bit < coverageBits);
            assert_int_equal(coverage[bit], 0);
            coverage[bit] = 1;
        }
    }
}

static void pcm_field_descriptors_cover_header(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        uint8_t coverage[AVTP_PCM_HEADER_LEN_V1 * 8] = {0};
        size_t coverageBits = sizeof(coverage);
        const Avtp_FieldDescriptor_t *pcmDesc =
            version == AVTP_VERSION_1 ? Avtp_PcmFieldDescV1 : Avtp_PcmFieldDescV0;
        size_t headerBits = (version == AVTP_VERSION_1 ? (size_t)AVTP_PCM_HEADER_LEN_V1
                                                       : (size_t)AVTP_PCM_HEADER_LEN_V0) *
                            8;

        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_SUBTYPE], 1);
        mark_descriptors(coverage, coverageBits,
                         &Avtp_CommonHeaderFieldDesc[AVTPDU_COMMON_FIELD_VERSION], 1);
        mark_descriptors(coverage, coverageBits, pcmDesc, AVTP_PCM_FIELD_MAX);

        for (size_t bit = 0; bit < coverageBits; bit++) {
            assert_int_equal(coverage[bit], bit < headerBits ? 1 : 0);
        }
    }
}

static void pcm_common_field_consistency(void **state)
{
    (void)state;

    assert_int_equal(AVTP_PCM_FIELD_STREAM_DATA_LENGTH, AVTPDU_CSH_FIELD_STREAM_DATA_LENGTH);

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *pcmDesc =
            version == AVTP_VERSION_1 ? Avtp_PcmFieldDescV1 : Avtp_PcmFieldDescV0;
        const Avtp_FieldDescriptor_t *cshDesc =
            version == AVTP_VERSION_1 ? Avtp_CshFieldDescV1 : Avtp_CshFieldDescV0;

        for (uint8_t i = 0; i < AVTPDU_CSH_FIELD_MAX; i++) {
            assert_int_equal(pcmDesc[i].quadlet, cshDesc[i].quadlet);
            assert_int_equal(pcmDesc[i].offset, cshDesc[i].offset);
            assert_int_equal(pcmDesc[i].bits, cshDesc[i].bits);
        }
    }
}

static void pcm_aaf_shared_field_consistency(void **state)
{
    (void)state;

    for (uint8_t version = 0; version <= 1; version++) {
        const Avtp_FieldDescriptor_t *pcmDesc =
            version == AVTP_VERSION_1 ? Avtp_PcmFieldDescV1 : Avtp_PcmFieldDescV0;
        const Avtp_FieldDescriptor_t *aafDesc =
            version == AVTP_VERSION_1 ? Avtp_AafFieldDescV1 : Avtp_AafFieldDescV0;

        /* PCM and AAF interpret the same format-specific data slots, so the
         * shared fields must have identical positions. */
        assert_memory_equal(&pcmDesc[AVTP_PCM_FIELD_FORMAT], &aafDesc[AVTP_AAF_FIELD_FORMAT],
                            sizeof(Avtp_FieldDescriptor_t));
        assert_memory_equal(&pcmDesc[AVTP_PCM_FIELD_SP], &aafDesc[AVTP_AAF_FIELD_SP],
                            sizeof(Avtp_FieldDescriptor_t));
        assert_memory_equal(&pcmDesc[AVTP_PCM_FIELD_EVT], &aafDesc[AVTP_AAF_FIELD_EVT],
                            sizeof(Avtp_FieldDescriptor_t));
        assert_memory_equal(&pcmDesc[AVTP_PCM_FIELD_STREAM_DATA_LENGTH],
                            &aafDesc[AVTP_AAF_FIELD_STREAM_DATA_LENGTH],
                            sizeof(Avtp_FieldDescriptor_t));
    }
}

static void pcm_flag_fields(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    Avtp_Pcm_Init(pcm);
    assert_true(Avtp_Pcm_IsSv(pcm));

    Avtp_Pcm_SetSv(pcm, false);
    assert_false(Avtp_Pcm_IsSv(pcm));

    Avtp_Pcm_SetMr(pcm, true);
    assert_true(Avtp_Pcm_IsMr(pcm));
    Avtp_Pcm_SetMr(pcm, false);
    assert_false(Avtp_Pcm_IsMr(pcm));

    Avtp_Pcm_SetTv(pcm, true);
    assert_true(Avtp_Pcm_IsTv(pcm));
    Avtp_Pcm_SetTv(pcm, false);
    assert_false(Avtp_Pcm_IsTv(pcm));

    Avtp_Pcm_SetTu(pcm, true);
    assert_true(Avtp_Pcm_IsTu(pcm));
    Avtp_Pcm_SetTu(pcm, false);
    assert_false(Avtp_Pcm_IsTu(pcm));

    Avtp_Pcm_SetSp(pcm, true);
    assert_true(Avtp_Pcm_IsSp(pcm));
    Avtp_Pcm_SetSp(pcm, false);
    assert_false(Avtp_Pcm_IsSp(pcm));
}

static void pcm_field_layout(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetSequenceNum(pcm, 0x55);
    assert_int_equal(Avtp_Pcm_GetSequenceNum(pcm), 0x55);
    assert_int_equal(read_quadlet(pdu, 0), 0x00005500);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetStreamId(pcm, 0xAABBCCDDEEFF0001);
    assert_int_equal(Avtp_Pcm_GetStreamId(pcm), 0xAABBCCDDEEFF0001);

    Avtp_Pcm_SetAvtpTimestamp(pcm, 0x80C0FFEE);
    assert_int_equal(Avtp_Pcm_GetAvtpTimestamp(pcm), 0x80C0FFEE);
    assert_int_equal(read_quadlet(pdu, 3), 0x80C0FFEE);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_INT_16BIT);
    assert_int_equal(Avtp_Pcm_GetFormat(pcm), AVTP_AAF_FORMAT_INT_16BIT);
    assert_int_equal(read_quadlet(pdu, 4), 0x04000000);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetNsr(pcm, AVTP_PCM_NSR_48KHZ);
    assert_int_equal(Avtp_Pcm_GetNsr(pcm), AVTP_PCM_NSR_48KHZ);
    assert_int_equal(read_quadlet(pdu, 4), 0x00500000);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetChannelsPerFrame(pcm, 0x2AA);
    assert_int_equal(Avtp_Pcm_GetChannelsPerFrame(pcm), 0x2AA);
    assert_int_equal(read_quadlet(pdu, 4), 0x0002AA00);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetBitDepth(pcm, 0xA5);
    assert_int_equal(Avtp_Pcm_GetBitDepth(pcm), 0xA5);
    assert_int_equal(read_quadlet(pdu, 4), 0x000000A5);

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetStreamDataLength(pcm, 0xAAAA);
    assert_int_equal(Avtp_Pcm_GetStreamDataLength(pcm), 0xAAAA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA0000);

    Avtp_Pcm_SetSp(pcm, true);
    assert_true(Avtp_Pcm_IsSp(pcm));
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA1000);

    Avtp_Pcm_SetEvt(pcm, 0xA);
    assert_int_equal(Avtp_Pcm_GetEvt(pcm), 0xA);
    assert_int_equal(read_quadlet(pdu, 5), 0xAAAA1A00);

    /* ptp_grandmaster_identity does not exist in version 0. */
    assert_int_equal(Avtp_Pcm_GetPtpGrandmasterIdentity(pcm), 0);
}

static void pcm_v1_layout(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_PCM_HEADER_LEN_V1];
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    Avtp_Pcm_InitV1((Avtp_PcmV1_t *)pdu);

    Avtp_Pcm_SetSequenceNum(pcm, 0x12345678);
    assert_int_equal(Avtp_Pcm_GetSequenceNum(pcm), 0x12345678);
    assert_int_equal(read_quadlet(pdu, 3), 0x12345678);

    Avtp_Pcm_SetAvtpTimestamp(pcm, 0x1122334455667788ULL);
    assert_int_equal(Avtp_Pcm_GetAvtpTimestamp(pcm), 0x1122334455667788ULL);
    assert_int_equal(read_quadlet(pdu, 4), 0x11223344);
    assert_int_equal(read_quadlet(pdu, 5), 0x55667788);

    Avtp_Pcm_SetPtpGrandmasterIdentity(pcm, 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Pcm_GetPtpGrandmasterIdentity(pcm), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(read_quadlet(pdu, 6), 0x99AABBCC);
    assert_int_equal(read_quadlet(pdu, 7), 0xDDEEFF00);

    Avtp_Pcm_SetFormat(pcm, AVTP_AAF_FORMAT_INT_16BIT);
    assert_int_equal(read_quadlet(pdu, 8), 0x04000000);

    Avtp_Pcm_SetNsr(pcm, AVTP_PCM_NSR_48KHZ);
    assert_int_equal(read_quadlet(pdu, 8), 0x04500000);

    Avtp_Pcm_SetChannelsPerFrame(pcm, 0x2AA);
    assert_int_equal(read_quadlet(pdu, 8), 0x0452AA00);

    Avtp_Pcm_SetBitDepth(pcm, 0xA5);
    assert_int_equal(read_quadlet(pdu, 8), 0x0452AAA5);

    Avtp_Pcm_SetStreamDataLength(pcm, 0xAAAA);
    Avtp_Pcm_SetSp(pcm, true);
    Avtp_Pcm_SetEvt(pcm, 0xA);
    assert_int_equal(read_quadlet(pdu, 9), 0xAAAA1A00);
}

static void pcm_payload(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    uint8_t payload_out[8] = {0};
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    Avtp_Pcm_Init(pcm);
    Avtp_Pcm_SetPayload(pcm, payload, sizeof(payload));

    assert_ptr_equal(Avtp_Pcm_GetPayload(pcm), pdu + AVTP_PCM_HEADER_LEN_V0);
    assert_memory_equal(pdu + AVTP_PCM_HEADER_LEN_V0, payload, sizeof(payload));

    memcpy(payload_out, Avtp_Pcm_GetPayload(pcm), sizeof(payload_out));
    assert_memory_equal(payload_out, payload, sizeof(payload_out));

    /* Version 1 payload starts after the 40-octet header. */
    Avtp_Pcm_InitV1((Avtp_PcmV1_t *)pdu);
    Avtp_Pcm_SetPayload((Avtp_Pcm_t *)pdu, payload, sizeof(payload));
    assert_ptr_equal(Avtp_Pcm_GetPayload((Avtp_Pcm_t *)pdu), pdu + AVTP_PCM_HEADER_LEN_V1);
    assert_memory_equal(pdu + AVTP_PCM_HEADER_LEN_V1, payload, sizeof(payload));
}

static void pcm_get_set_field(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    memset(pdu, 0, MAX_PDU_SIZE);

    Avtp_Pcm_SetField(pcm, AVTP_PCM_FIELD_EVT, 0xA);
    assert_int_equal(Avtp_Pcm_GetField(pcm, AVTP_PCM_FIELD_EVT), 0xA);

    /* Reserved fields are reachable through the generic access engine. */
    Avtp_Pcm_SetField(pcm, AVTP_PCM_FIELD_FSD, 0x3);
    assert_int_equal(Avtp_Pcm_GetField(pcm, AVTP_PCM_FIELD_FSD), 0x3);

    Avtp_Pcm_SetField(pcm, AVTP_PCM_FIELD_RESERVED2, 0xAB);
    assert_int_equal(Avtp_Pcm_GetField(pcm, AVTP_PCM_FIELD_RESERVED2), 0xAB);
}

static void pcm_typed_fields_v0(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_PCM_HEADER_LEN_V1];
    Avtp_Pcm_t *pcm = (Avtp_Pcm_t *)pdu;

    Avtp_Pcm_Init(pcm);

    for (uint8_t f = 0; f < AVTP_PCM_FIELD_MAX; f++) {
        uint8_t bits = Avtp_PcmFieldDescV0[f].bits;
        uint64_t value = 0xA5A5A5A5A5A5A5A5ULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_PcmFields_t field = (Avtp_PcmFields_t)f;

        Avtp_Pcm_SetField_V0(pcm, field, value);
        assert_int_equal(Avtp_Pcm_GetField_V0(pcm, field), expected);
        assert_int_equal(Avtp_Pcm_GetField(pcm, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_PcmFieldDescV0, AVTP_PCM_FIELD_MAX, pdu, f), expected);
    }
}

static void pcm_typed_fields_v1(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_PCM_HEADER_LEN_V1];
    Avtp_PcmV1_t *pcm = (Avtp_PcmV1_t *)pdu;

    Avtp_Pcm_InitV1(pcm);

    for (uint8_t f = 0; f < AVTP_PCM_FIELD_MAX; f++) {
        uint8_t bits = Avtp_PcmFieldDescV1[f].bits;
        uint64_t value = 0x5A5A5A5A5A5A5A5AULL ^ (uint64_t)f;
        uint64_t expected = mask_field_value(bits, value);
        Avtp_PcmFields_t field = (Avtp_PcmFields_t)f;

        Avtp_Pcm_SetField_V1(pcm, field, value);
        assert_int_equal(Avtp_Pcm_GetField_V1(pcm, field), expected);
        assert_int_equal(Avtp_Pcm_GetField((Avtp_Pcm_t *)pcm, field), expected);
        assert_int_equal(Avtp_GetField(Avtp_PcmFieldDescV1, AVTP_PCM_FIELD_MAX, pdu, f), expected);
    }
}

static void pcm_typed_named(void **state)
{
    (void)state;
    uint8_t pdu[AVTP_PCM_HEADER_LEN_V1];
    Avtp_Pcm_t *v0 = (Avtp_Pcm_t *)pdu;
    Avtp_PcmV1_t *v1 = (Avtp_PcmV1_t *)pdu;

    /* Version 0. */
    Avtp_Pcm_Init(v0);
    Avtp_Pcm_SetSv_V0(v0, true);
    Avtp_Pcm_SetSequenceNum_V0(v0, 0x55);
    Avtp_Pcm_SetStreamId_V0(v0, 0xAABBCCDDEEFF0001ULL);
    Avtp_Pcm_SetAvtpTimestamp_V0(v0, 0x80C0FFEE);
    Avtp_Pcm_SetFormat_V0(v0, AVTP_AAF_FORMAT_INT_16BIT);
    Avtp_Pcm_SetNsr_V0(v0, AVTP_PCM_NSR_48KHZ);
    Avtp_Pcm_SetChannelsPerFrame_V0(v0, 2);
    Avtp_Pcm_SetBitDepth_V0(v0, 16);
    Avtp_Pcm_SetStreamDataLength_V0(v0, 0xAAAA);
    Avtp_Pcm_SetSp_V0(v0, true);
    Avtp_Pcm_SetEvt_V0(v0, 0xA);

    assert_true(Avtp_Pcm_IsSv_V0(v0));
    assert_int_equal(Avtp_Pcm_GetSequenceNum_V0(v0), 0x55);
    assert_int_equal(Avtp_Pcm_GetStreamId_V0(v0), 0xAABBCCDDEEFF0001ULL);
    assert_int_equal(Avtp_Pcm_GetAvtpTimestamp_V0(v0), 0x80C0FFEE);
    assert_int_equal(Avtp_Pcm_GetFormat_V0(v0), AVTP_AAF_FORMAT_INT_16BIT);
    assert_int_equal(Avtp_Pcm_GetNsr_V0(v0), AVTP_PCM_NSR_48KHZ);
    assert_int_equal(Avtp_Pcm_GetChannelsPerFrame_V0(v0), 2);
    assert_int_equal(Avtp_Pcm_GetBitDepth_V0(v0), 16);
    assert_int_equal(Avtp_Pcm_GetStreamDataLength_V0(v0), 0xAAAA);
    assert_true(Avtp_Pcm_IsSp_V0(v0));
    assert_int_equal(Avtp_Pcm_GetEvt_V0(v0), 0xA);
    assert_int_equal(Avtp_Pcm_GetPtpGrandmasterIdentity_V0(v0), 0);

    /* The version-dispatched accessors agree with the version 0 variants. */
    assert_int_equal(Avtp_Pcm_GetSequenceNum(v0), Avtp_Pcm_GetSequenceNum_V0(v0));
    assert_int_equal(Avtp_Pcm_GetStreamId(v0), Avtp_Pcm_GetStreamId_V0(v0));
    assert_int_equal(Avtp_Pcm_GetAvtpTimestamp(v0), Avtp_Pcm_GetAvtpTimestamp_V0(v0));
    assert_int_equal(Avtp_Pcm_GetFormat(v0), Avtp_Pcm_GetFormat_V0(v0));
    assert_int_equal(Avtp_Pcm_GetNsr(v0), Avtp_Pcm_GetNsr_V0(v0));
    assert_int_equal(Avtp_Pcm_GetChannelsPerFrame(v0), Avtp_Pcm_GetChannelsPerFrame_V0(v0));
    assert_int_equal(Avtp_Pcm_GetBitDepth(v0), Avtp_Pcm_GetBitDepth_V0(v0));
    assert_int_equal(Avtp_Pcm_GetStreamDataLength(v0), Avtp_Pcm_GetStreamDataLength_V0(v0));
    assert_int_equal(Avtp_Pcm_GetEvt(v0), Avtp_Pcm_GetEvt_V0(v0));

    /* Version 1. */
    Avtp_Pcm_InitV1(v1);
    Avtp_Pcm_SetSv_V1(v1, true);
    Avtp_Pcm_SetSequenceNum_V1(v1, 0x12345678);
    Avtp_Pcm_SetStreamId_V1(v1, 0x0102030405060708ULL);
    Avtp_Pcm_SetAvtpTimestamp_V1(v1, 0x1122334455667788ULL);
    Avtp_Pcm_SetPtpGrandmasterIdentity_V1(v1, 0x99AABBCCDDEEFF00ULL);
    Avtp_Pcm_SetFormat_V1(v1, AVTP_AAF_FORMAT_FLOAT_32BIT);
    Avtp_Pcm_SetNsr_V1(v1, AVTP_PCM_NSR_96KHZ);
    Avtp_Pcm_SetChannelsPerFrame_V1(v1, 8);
    Avtp_Pcm_SetBitDepth_V1(v1, 32);
    Avtp_Pcm_SetStreamDataLength_V1(v1, 0xBBBB);
    Avtp_Pcm_SetSp_V1(v1, true);
    Avtp_Pcm_SetEvt_V1(v1, 0xB);

    assert_true(Avtp_Pcm_IsSv_V1(v1));
    assert_int_equal(Avtp_Pcm_GetSequenceNum_V1(v1), 0x12345678);
    assert_int_equal(Avtp_Pcm_GetStreamId_V1(v1), 0x0102030405060708ULL);
    assert_int_equal(Avtp_Pcm_GetAvtpTimestamp_V1(v1), 0x1122334455667788ULL);
    assert_int_equal(Avtp_Pcm_GetPtpGrandmasterIdentity_V1(v1), 0x99AABBCCDDEEFF00ULL);
    assert_int_equal(Avtp_Pcm_GetFormat_V1(v1), AVTP_AAF_FORMAT_FLOAT_32BIT);
    assert_int_equal(Avtp_Pcm_GetNsr_V1(v1), AVTP_PCM_NSR_96KHZ);
    assert_int_equal(Avtp_Pcm_GetChannelsPerFrame_V1(v1), 8);
    assert_int_equal(Avtp_Pcm_GetBitDepth_V1(v1), 32);
    assert_int_equal(Avtp_Pcm_GetStreamDataLength_V1(v1), 0xBBBB);
    assert_true(Avtp_Pcm_IsSp_V1(v1));
    assert_int_equal(Avtp_Pcm_GetEvt_V1(v1), 0xB);

    /* The version-dispatched accessors agree with the version 1 variants. */
    assert_int_equal(Avtp_Pcm_GetSequenceNum(v0), Avtp_Pcm_GetSequenceNum_V1(v1));
    assert_int_equal(Avtp_Pcm_GetStreamId(v0), Avtp_Pcm_GetStreamId_V1(v1));
    assert_int_equal(Avtp_Pcm_GetAvtpTimestamp(v0), Avtp_Pcm_GetAvtpTimestamp_V1(v1));
    assert_int_equal(Avtp_Pcm_GetPtpGrandmasterIdentity(v0),
                     Avtp_Pcm_GetPtpGrandmasterIdentity_V1(v1));
    assert_int_equal(Avtp_Pcm_GetFormat(v0), Avtp_Pcm_GetFormat_V1(v1));
    assert_int_equal(Avtp_Pcm_GetNsr(v0), Avtp_Pcm_GetNsr_V1(v1));
    assert_int_equal(Avtp_Pcm_GetChannelsPerFrame(v0), Avtp_Pcm_GetChannelsPerFrame_V1(v1));
    assert_int_equal(Avtp_Pcm_GetBitDepth(v0), Avtp_Pcm_GetBitDepth_V1(v1));
    assert_int_equal(Avtp_Pcm_GetStreamDataLength(v0), Avtp_Pcm_GetStreamDataLength_V1(v1));
    assert_int_equal(Avtp_Pcm_GetEvt(v0), Avtp_Pcm_GetEvt_V1(v1));
}

static void pcm_typed_helpers(void **state)
{
    (void)state;
    uint8_t pdu[MAX_PDU_SIZE];
    uint8_t payload[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

    Avtp_Pcm_Init((Avtp_Pcm_t *)pdu);
    assert_int_equal(Avtp_Pcm_GetHeaderLen_V0((Avtp_Pcm_t *)pdu), AVTP_PCM_HEADER_LEN_V0);
    assert_ptr_equal(Avtp_Pcm_GetPayload_V0((Avtp_Pcm_t *)pdu), pdu + AVTP_PCM_HEADER_LEN_V0);
    Avtp_Pcm_SetPayload_V0((Avtp_Pcm_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_PCM_HEADER_LEN_V0, payload, sizeof(payload));

    Avtp_Pcm_InitV1((Avtp_PcmV1_t *)pdu);
    assert_int_equal(Avtp_Pcm_GetHeaderLen_V1((Avtp_PcmV1_t *)pdu), AVTP_PCM_HEADER_LEN_V1);
    assert_ptr_equal(Avtp_Pcm_GetPayload_V1((Avtp_PcmV1_t *)pdu), pdu + AVTP_PCM_HEADER_LEN_V1);
    Avtp_Pcm_SetPayload_V1((Avtp_PcmV1_t *)pdu, payload, sizeof(payload));
    assert_memory_equal(pdu + AVTP_PCM_HEADER_LEN_V1, payload, sizeof(payload));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(pcm_init),
        cmocka_unit_test(pcm_init_v1),
        cmocka_unit_test(pcm_is_valid),
        cmocka_unit_test(pcm_field_descriptors_cover_header),
        cmocka_unit_test(pcm_common_field_consistency),
        cmocka_unit_test(pcm_aaf_shared_field_consistency),
        cmocka_unit_test(pcm_flag_fields),
        cmocka_unit_test(pcm_field_layout),
        cmocka_unit_test(pcm_v1_layout),
        cmocka_unit_test(pcm_payload),
        cmocka_unit_test(pcm_get_set_field),
        cmocka_unit_test(pcm_typed_fields_v0),
        cmocka_unit_test(pcm_typed_fields_v1),
        cmocka_unit_test(pcm_typed_named),
        cmocka_unit_test(pcm_typed_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
