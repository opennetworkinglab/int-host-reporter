// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"strings"
)

const (
	// PossibleCPUSysfsPath is used to retrieve the number of CPUs for per-CPU maps.
	PossibleCPUSysfsPath = "/sys/devices/system/cpu/possible"
)

func ToNetIP(val uint32) net.IP {
	return net.IPv4(byte(val&0xFF), byte(val>>8)&0xFF,
		byte(val>>16)&0xFF, byte(val>>24)&0xFF)
}

func ParseCNIType(cniName string) error {
	if cniName == "" {
		return fmt.Errorf("CNI implementation not provided")
	}

	switch cniName {
	case "cilium":
		CNITypeInUse = CNITypeCilium
	case "calico-ebpf":
		CNITypeInUse = CNITypeCalicoEBPF
	case "calico-iptables":
		CNITypeInUse = CNITypeCalicoIPTables
	default:
		return fmt.Errorf("CNI type not supported")
	}

	return nil
}

func IsManagedByCilium(intfName string) bool {
	if strings.Contains(intfName, "lxc") && intfName != "lxc_health" {
		return true
	}

	return false
}

func IsManagedByCalico(intfName string) bool {
	if strings.Contains(intfName, "cali") && intfName != "vxlan.calico" { // Calico
		return true
	}
	return false
}

func IsInterfaceManagedByCNI(intfName string) bool {
	switch CNITypeInUse {
	case CNITypeCilium:
		return IsManagedByCilium(intfName)
	case CNITypeCalicoEBPF, CNITypeCalicoIPTables:
		return IsManagedByCalico(intfName)
	default:
		return false
	}
}

func GetNumPossibleCPUs() int {
	f, err := os.Open(PossibleCPUSysfsPath)
	if err != nil {
		log.WithError(err).Errorf("unable to open %q", PossibleCPUSysfsPath)
		return 0
	}
	defer f.Close()

	return getNumPossibleCPUsFromReader(f)
}

func getNumPossibleCPUsFromReader(r io.Reader) int {
	out, err := io.ReadAll(r)
	if err != nil {
		log.WithError(err).Errorf("unable to read %q to get CPU count", PossibleCPUSysfsPath)
		return 0
	}

	var start, end int
	count := 0
	for _, s := range strings.Split(string(out), ",") {
		// Go's scanf will return an error if a format cannot be fully matched.
		// So, just ignore it, as a partial match (e.g. when there is only one
		// CPU) is expected.
		n, err := fmt.Sscanf(s, "%d-%d", &start, &end)

		switch n {
		case 0:
			log.WithError(err).Errorf("failed to scan %q to retrieve number of possible CPUs!", s)
			return 0
		case 1:
			count++
		default:
			count += (end - start + 1)
		}
	}

	return count
}