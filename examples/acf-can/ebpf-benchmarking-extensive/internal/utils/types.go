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

package utils

import "net/netip"

// Config type that needs to be passed to the ebpf program
type Config struct {
	PidTalker   uint32
	PidListener uint32
	PidCangen   uint32
	SrcIP       [4]byte
	DstIP       [4]byte
	SrcPort     uint32
	DstPort     uint32
	IsKernel    bool
}

type EventTrace struct {
	Timestamp uint64
	Pid       uint32
	Uid       uint32
	Function  [32]byte // char[32] -> fixed-size array of 32 bytes
	Dev       [32]byte
}

type EventTraceRxKernel struct {
	Timestamp uint64
	Dev       [32]byte
}

type EventLog struct {
	Pid                     uint32
	Dev                     string
	TimestampEnterRead      uint64
	TimestampExitRead       uint64
	TimestampEnterSendto    uint64
	TimestampExitSendto     uint64
	TimestampEnterCanToAvtp uint64
	TimestampExitCanToAvtp  uint64
	TimestampEnterAvtpToCan uint64
	TimestampExitAvtpToCan  uint64

	TimeReadingCANBus uint64
	TimeWriting       uint64
	TimeCanToAvtp     uint64
	TimeAvtpToCan     uint64
}

type Flags struct {
	PidListener uint
	PidTalker   uint
	PidCangen   uint
	_SrcIP      string
	SrcIP       netip.Addr
	_DstIP      string
	DstIP       netip.Addr
	SrcPort     uint
	DstPort     uint
	IsKernel    bool //TODO: Add more filters like protocol, check, etc

	TalkerFile   string
	ListenerFile string
}
