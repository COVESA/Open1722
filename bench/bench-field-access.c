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

/**
 * @file
 * Micro-benchmark comparing version-typed accessors, version-agnostic
 * accessors and raw bit access on the same PDUs.
 *
 * Build a Release build and run:
 *
 *     cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release
 *     cmake --build build-bench --target bench-field-access -j"$(nproc)"
 *     ./build-bench/bench/bench-field-access
 *
 * The absolute numbers depend on the machine; the point is the ratio between
 * the typed and the raw column. A version-typed accessor should be within a
 * few percent of the raw access, while the agnostic variant pays one version
 * load and branch on top. See README.md and check-folding.sh.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "avtp/Byteorder.h"
#include "avtp/Rvf.h"
#include "avtp/acf/Tscf.h"

#define ITERATIONS 20000000u

static volatile uint64_t sink;

/*
 * Keeps the compiler from hoisting loop-invariant loads or coalescing the
 * stores; it is applied to every variant equally.
 */
#if defined(__GNUC__)
#define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#else
#define COMPILER_BARRIER() (sink ^= 1u)
#endif

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

#define BENCH(label, body)                                                                         \
    do {                                                                                           \
        uint64_t bench_sum = 0;                                                                    \
        uint64_t bench_start = now_ns();                                                           \
        for (uint32_t bench_i = 0; bench_i < ITERATIONS; bench_i++) {                              \
            COMPILER_BARRIER();                                                                    \
            body;                                                                                  \
        }                                                                                          \
        uint64_t bench_elapsed = now_ns() - bench_start;                                           \
        sink += bench_sum;                                                                         \
        printf("  %-40s %8.3f ns/op\n", label, (double)bench_elapsed / (double)ITERATIONS);        \
    } while (0)

static uint32_t raw_be32(const uint8_t *p)
{
    uint32_t value;

    memcpy(&value, p, sizeof(value));
    return Avtp_BeToCpu32(value);
}

static void bench_tscf_v1_get(void)
{
    uint8_t buf[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_TscfV1_t *pdu = (Avtp_TscfV1_t *)buf;

    Avtp_Tscf_InitV1(pdu);
    Avtp_Tscf_SetSequenceNum_V1(pdu, 0x12345678);

    printf("TSCF version 1, get sequence_num (32 bit):\n");
    BENCH("typed    Avtp_Tscf_GetSequenceNum_V1", bench_sum += Avtp_Tscf_GetSequenceNum_V1(pdu));
    BENCH("agnostic Avtp_Tscf_GetSequenceNum",
          bench_sum += Avtp_Tscf_GetSequenceNum((const Avtp_Tscf_t *)pdu));
    BENCH("raw      be32(header + 12)", bench_sum += raw_be32(pdu->header + 12));
}

static void bench_tscf_v1_set(void)
{
    uint8_t buf[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_TscfV1_t *pdu = (Avtp_TscfV1_t *)buf;

    Avtp_Tscf_InitV1(pdu);

    printf("TSCF version 1, set sequence_num (32 bit + lsb copy):\n");
    BENCH("typed    Avtp_Tscf_SetSequenceNum_V1", Avtp_Tscf_SetSequenceNum_V1(pdu, bench_i);
          bench_sum += pdu->header[15]);
    BENCH("agnostic Avtp_Tscf_SetSequenceNum",
          Avtp_Tscf_SetSequenceNum((Avtp_Tscf_t *)pdu, bench_i);
          bench_sum += pdu->header[15]);
    BENCH("raw      two stores", uint32_t raw = Avtp_CpuToBe32(bench_i);
          memcpy(pdu->header + 12, &raw, sizeof(raw)); pdu->header[2] = (uint8_t)bench_i;
          bench_sum += pdu->header[15]);
}

static void bench_tscf_v0_get(void)
{
    uint8_t buf[AVTP_TSCF_HEADER_LEN_V0];
    Avtp_Tscf_t *pdu = (Avtp_Tscf_t *)buf;

    Avtp_Tscf_Init(pdu);
    Avtp_Tscf_SetSequenceNum_V0(pdu, 0xAB);

    printf("TSCF version 0, get sequence_num (8 bit):\n");
    BENCH("typed    Avtp_Tscf_GetSequenceNum_V0", bench_sum += Avtp_Tscf_GetSequenceNum_V0(pdu));
    BENCH("agnostic Avtp_Tscf_GetSequenceNum", bench_sum += Avtp_Tscf_GetSequenceNum(pdu));
    BENCH("raw      (be32(header) >> 8) & 0xff", bench_sum += (raw_be32(pdu->header) >> 8) & 0xFFU);
}

static void bench_tscf_v0_set(void)
{
    uint8_t buf[AVTP_TSCF_HEADER_LEN_V0];
    Avtp_Tscf_t *pdu = (Avtp_Tscf_t *)buf;

    Avtp_Tscf_Init(pdu);

    printf("TSCF version 0, set sequence_num (8 bit):\n");
    BENCH("typed    Avtp_Tscf_SetSequenceNum_V0", Avtp_Tscf_SetSequenceNum_V0(pdu, bench_i);
          bench_sum += pdu->header[15]);
    BENCH("agnostic Avtp_Tscf_SetSequenceNum", Avtp_Tscf_SetSequenceNum(pdu, bench_i);
          bench_sum += pdu->header[15]);
    BENCH("raw      one store", pdu->header[2] = (uint8_t)bench_i; bench_sum += pdu->header[15]);
}

static void bench_tscf_v1_stream_id(void)
{
    uint8_t buf[AVTP_TSCF_HEADER_LEN_V1];
    Avtp_TscfV1_t *pdu = (Avtp_TscfV1_t *)buf;

    Avtp_Tscf_InitV1(pdu);
    Avtp_Tscf_SetStreamId_V1(pdu, 0x0102030405060708ULL);

    printf("TSCF version 1, get stream_id (64 bit, two quadlets):\n");
    BENCH("typed    Avtp_Tscf_GetStreamId_V1", bench_sum += Avtp_Tscf_GetStreamId_V1(pdu));
    BENCH("agnostic Avtp_Tscf_GetStreamId",
          bench_sum += Avtp_Tscf_GetStreamId((const Avtp_Tscf_t *)pdu));
    BENCH("raw      two be32 loads", bench_sum += ((uint64_t)raw_be32(pdu->header + 4) << 32) |
                                                  (uint64_t)raw_be32(pdu->header + 8));
}

static void bench_rvf_v1_active_pixels(void)
{
    uint8_t buf[AVTP_RVF_HEADER_LEN_V1];
    Avtp_RvfV1_t *pdu = (Avtp_RvfV1_t *)buf;

    Avtp_Rvf_InitV1(pdu);
    Avtp_Rvf_SetActivePixels_V1(pdu, 1920);

    printf("RVF version 1, get active_pixels (format-specific, 16 bit):\n");
    BENCH("typed    Avtp_Rvf_GetActivePixels_V1", bench_sum += Avtp_Rvf_GetActivePixels_V1(pdu));
    BENCH("agnostic Avtp_Rvf_GetActivePixels",
          bench_sum += Avtp_Rvf_GetActivePixels((const Avtp_Rvf_t *)pdu));
    BENCH("raw      be32(header + 32) >> 16", bench_sum += raw_be32(pdu->header + 32) >> 16);
}

int main(void)
{
    printf("bench-field-access: %u iterations per measurement, compiler %s\n\n", ITERATIONS,
           __VERSION__);

    bench_tscf_v1_get();
    bench_tscf_v1_set();
    bench_tscf_v0_get();
    bench_tscf_v0_set();
    bench_tscf_v1_stream_id();
    bench_rvf_v1_active_pixels();

    printf("\nsink=%" PRIu64 " (prevents the compiler from discarding the loops)\n", sink);

    return 0;
}
