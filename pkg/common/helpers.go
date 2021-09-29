package common

import (
	"fmt"
	"net"
	"strings"
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

func IsManagedByCalicoEBPF(intfName string) bool {
	if strings.Contains(intfName, "cali") && intfName != "vxlan.calico" { // Calico
		return true
	}
	return false
}

func IsInterfaceManagedByCNI(intfName string) bool {
	switch CNITypeInUse {
	case CNITypeCilium:
		return IsManagedByCilium(intfName)
	case CNITypeCalicoEBPF:
		return IsManagedByCalicoEBPF(intfName)
	default:
		return false
	}
}