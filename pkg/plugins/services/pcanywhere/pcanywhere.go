// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package pcanywhere implements service detection for Symantec pcAnywhere.

Detection uses documented handshakes, not HTTP banners:

  - TCP 5631: client hello of four NUL bytes. A pcAnywhere host replies
    with "ST" (GIAC GCIA analyses of the proprietary handshake). Nmap
    also fingerprints the unsolicited TCP banner starting \0X\x08\0}\x08
    (match pcanywheredata) and the \x1bY2 probe response (match pc-anywhere).
  - UDP 5632: Nmap probe "NQ"; host replies NR{name}_*AHM_3___\0
    (nmap-service-probes Probe UDP pc-anywhere).
*/
package pcanywhere

import (
	"bytes"
	"encoding/hex"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const PCANYWHERE = "pcanywhere"

// tcpHello is the documented four-NUL client hello on the data channel.
var tcpHello = []byte{0x00, 0x00, 0x00, 0x00}

// udpStatusProbe is Nmap's UDP pc-anywhere probe ("NQ") on port 5632.
var udpStatusProbe = []byte("NQ")

type PcAnywherePlugin struct{}

type PcAnywhereUDPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&PcAnywherePlugin{})
	plugins.RegisterPlugin(&PcAnywhereUDPPlugin{})
}

func checkPcAnywhereTCP(data []byte) error {
	invalid := &utils.InvalidResponseErrorInfo{
		Service: PCANYWHERE,
		Info:    "not a pcAnywhere TCP handshake",
	}
	if len(data) < 2 {
		invalid.Info = "response too short"
		return invalid
	}
	// GIAC: host responds with "ST" in the first two payload bytes.
	if data[0] == 'S' && data[1] == 'T' {
		return nil
	}
	// Nmap NULL probe: match pcanywheredata m|^\0X\x08\0\}\x08
	if len(data) >= 6 &&
		data[0] == 0x00 && data[1] == 'X' && data[2] == 0x08 &&
		data[3] == 0x00 && data[4] == '}' && data[5] == 0x08 {
		return nil
	}
	// Nmap match pc-anywhere m|\x1bY2\0\x01\x03B
	if len(data) >= 3 && data[0] == 0x1b && data[1] == 'Y' && data[2] == '2' {
		return nil
	}
	return invalid
}

func checkPcAnywhereUDP(data []byte) error {
	invalid := &utils.InvalidResponseErrorInfo{
		Service: PCANYWHERE,
		Info:    "not a pcAnywhere UDP status reply",
	}
	if len(data) < 2 || data[0] != 'N' || data[1] != 'R' {
		return invalid
	}
	// Nmap: ^NR([^_]*)_*AHM_3___\0
	if !bytes.Contains(data, []byte("AHM_3___")) {
		return invalid
	}
	return nil
}

func emitService(target plugins.Target, transport plugins.Protocol, evidence string) *plugins.Service {
	service := plugins.CreateServiceFrom(target, plugins.ServicePcAnywhere{
		CPEs: []string{"cpe:2.3:a:symantec:pcanywhere:*:*:*:*:*:*:*:*"},
	}, false, "", transport)
	if target.Misconfigs {
		service.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "pcanywhere-exposed",
			Severity:    plugins.SeverityMedium,
			Description: "pcAnywhere remote access listener exposed to the network",
			Evidence:    evidence,
		}}
	}
	return service
}

func (p *PcAnywherePlugin) PortPriority(port uint16) bool {
	return port == 5631
}

func (p *PcAnywherePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, tcpHello, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	if err := checkPcAnywhereTCP(response); err != nil {
		return nil, nil
	}
	n := 2
	if len(response) < n {
		n = len(response)
	}
	return emitService(target, plugins.TCP, "tcp="+hex.EncodeToString(response[:n])), nil
}

func (p *PcAnywherePlugin) Name() string { return PCANYWHERE }

func (p *PcAnywherePlugin) Type() plugins.Protocol { return plugins.TCP }

func (p *PcAnywherePlugin) Priority() int { return 100 }

func (p *PcAnywhereUDPPlugin) PortPriority(port uint16) bool {
	return port == 5632
}

func (p *PcAnywhereUDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, udpStatusProbe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	if err := checkPcAnywhereUDP(response); err != nil {
		return nil, nil
	}
	return emitService(target, plugins.UDP, "udp=NR"), nil
}

func (p *PcAnywhereUDPPlugin) Name() string { return PCANYWHERE }

func (p *PcAnywhereUDPPlugin) Type() plugins.Protocol { return plugins.UDP }

func (p *PcAnywhereUDPPlugin) Priority() int { return 100 }
