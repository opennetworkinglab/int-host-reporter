// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"github.com/gin-gonic/gin"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/system"
	"net"
	"net/http"
)

// Represents local link inside a host.
type localLink struct {
	ID uint64 `json:"id"`
	Name string `json:"name"`
	IPs []net.IP `json:"ip-addresses"`
	NodeIface bool `json:"is-node-iface"`
}

type topology struct {
	Links []localLink `json:"links"`
}

func GetTopology(c *gin.Context) {
	var topologyData topology
	systemLinks := system.GetAllLinks()
	for _, sysLink := range systemLinks {
		l := localLink{
			ID:   sysLink.ID,
			Name: sysLink.Name,
			IPs: sysLink.IPAddresses,
			NodeIface: false,
		}
		if sysLink.Name == *common.DataInterface {
			l.NodeIface = true
		}
		topologyData.Links = append(topologyData.Links, l)
	}

	c.IndentedJSON(http.StatusOK, topologyData)
}
