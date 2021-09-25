package common

import (
	"net"
	"strings"
)

func ToNetIP(val uint32) net.IP {
	return net.IPv4(byte(val>>24), byte(val>>16&0xFF),
		byte(val>>8)&0xFF, byte(val&0xFF))
}

func IsInterfaceManagedByCNI(name string) bool {
	// Cilium
	if strings.Contains(name, "lxc") && name != "lxc_health" {
		return true
	} else if strings.Contains(name, "cali") && name != "vxlan.calico" {  // Calico
		return true
	}

	return false
}