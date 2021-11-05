// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
)

type SysLink struct {
	ID          uint64
	Name        string
	IPAddresses []net.IP
}

func GetAllLinks() []SysLink {
	log.Debug("Finding all local links in the system..")
	var systemLinks []SysLink
	links, _ := netlink.LinkList()
	for _, link := range links {
		if link.Attrs().Name == *common.DataInterface ||
			common.IsInterfaceManagedByCNI(link.Attrs().Name) {
			ipv4Addrs := []net.IP{}
			addrs, _ := netlink.AddrList(link, unix.AF_INET)
			for _, addr := range addrs {
				if addr.IP.To4() != nil {
					ipv4Addrs = append(ipv4Addrs, addr.IP.To4())
				}
			}
			l := SysLink{
				ID:          uint64(link.Attrs().Index),
				Name:        link.Attrs().Name,
				IPAddresses: ipv4Addrs,
			}
			log.WithFields(log.Fields{
				"name" : l.Name,
				"ID" : l.ID,
				"ip-addresses" : l.IPAddresses,
			}).Debug("Adding local link to the list.")
			systemLinks = append(systemLinks, l)
		}
	}
	return systemLinks
}
