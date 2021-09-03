package common

import "net"

func ToNetIP(val uint32) net.IP {
	return net.IPv4(byte(val>>24), byte(val>>16&0xFF),
		byte(val>>8)&0xFF, byte(val&0xFF))
}
