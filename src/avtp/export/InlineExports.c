/*
 * Copyright (c) 2026 COVESA
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

/*
 * Forces external definitions of all inline functions in the public headers.
 *
 * Phase 1 includes all transitive dependencies (Byteorder, Utils,
 * AcfCommon, etc.) in the default static-inline mode so they have
 * internal linkage and do not conflict between translation units.
 *
 * Phase 2 overrides OPEN1722_INLINE to empty and includes each target
 * header, making its inline functions regular extern definitions.
 */

/* --- Phase 1: shared deps (static-inline mode) ----------------------- */

#include <string.h>
#include "avtp/Inline.h"
#include "avtp/Defines.h"
#include "avtp/Byteorder.h"
#include "avtp/Utils.h"
#include "avtp/CommonHeader.h"
#include "avtp/acf/AcfCommon.h"

/* --- Phase 2: target headers (extern-definition mode) ---------------- */

#undef OPEN1722_INLINE
#define OPEN1722_INLINE

#include "avtp/Udp.h"

#include "avtp/acf/Abb.h"
#include "avtp/acf/Can.h"
#include "avtp/acf/CanBrief.h"
#include "avtp/acf/CanBriefV2.h"
#include "avtp/acf/CanV2.h"
#include "avtp/acf/CanXl.h"
#include "avtp/acf/CanXlBrief.h"
#include "avtp/acf/FlexRay.h"
#include "avtp/acf/Gbb.h"
#include "avtp/acf/Gisf.h"
#include "avtp/acf/Gpc.h"
#include "avtp/acf/Lin.h"
#include "avtp/acf/Most.h"
#include "avtp/acf/Ntscf.h"
#include "avtp/acf/Sensor.h"
#include "avtp/acf/SensorBrief.h"
#include "avtp/acf/Tscf.h"
