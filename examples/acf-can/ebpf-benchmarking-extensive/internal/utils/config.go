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

import (
	"flag"
	"net/netip"
)

func ParseFlags() (*Flags, error) {
	var f Flags

	flag.StringVar(&f._DstIP, "dest-ip", "127.0.0.1", "Destination IP")
	flag.StringVar(&f._SrcIP, "src-ip", "127.0.0.1", "Source IP")
	flag.UintVar(&f.SrcPort, "src-port", 0, "Source Port")
	flag.UintVar(&f.DstPort, "dst-port", 0, "Destination Port")

	flag.UintVar(&f.PidListener, "pid-listener", 0, "pid to filter")
	flag.UintVar(&f.PidTalker, "pid-talker", 0, "pid to filter")
	flag.UintVar(&f.PidCangen, "pid-cangen", 0, "pid to filter")
	flag.BoolVar(&f.IsKernel, "is-kernel", false, "Filter kernel packets")

	flag.StringVar(&f.TalkerFile, "talker-file", "", "File to write talker events")
	flag.StringVar(&f.ListenerFile, "listener-file", "", "File to write listener events")
	flag.Parse()

	if f._DstIP != "" {
		addr, err := netip.ParseAddr(f._DstIP)
		if err != nil {
			return nil, err
		}
		f.DstIP = addr
	}
	if f._SrcIP != "" {
		addr, err := netip.ParseAddr(f._SrcIP)
		if err != nil {
			return nil, err
		}
		f.SrcIP = addr
	}

	return &f, nil
}

func (f *Flags) GetConfig() *Config {
	var c Config
	c.PidTalker = uint32(f.PidTalker)
	c.PidListener = uint32(f.PidListener)
	c.PidCangen = uint32(f.PidCangen)
	c.SrcIP = f.SrcIP.As4()
	c.DstIP = f.DstIP.As4()
	c.SrcPort = uint32(f.SrcPort)
	c.DstPort = uint32(f.DstPort)
	c.IsKernel = f.IsKernel
	return &c
}
