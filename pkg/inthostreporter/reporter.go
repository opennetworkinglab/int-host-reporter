// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: LicenseRef-ONF-Member-1.0

package inthostreporter

import (
	"context"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"os/exec"
	"strings"
	"time"
)

const (
	INTProgramHandle = 3
)

type IntHostReporter struct {
	ctx              context.Context
	perfReaderCancel context.CancelFunc

	reportHandler      *ReportHandler
	dataPlaneInterface *dataplane.DataPlaneInterface
}

func NewIntHostReporter(watchlist *watchlist.INTWatchlist) *IntHostReporter {
	itr := &IntHostReporter{}
	itr.ctx = context.Background()
	itr.dataPlaneInterface = dataplane.NewDataPlaneInterface()
	itr.reportHandler = NewReportHandler(itr.dataPlaneInterface)
	itr.initWatchlist(watchlist)
	return itr
}

func (itr *IntHostReporter) initWatchlist(watchlist *watchlist.INTWatchlist) {
	if len(watchlist.GetRules()) > 0 {
		log.WithFields(log.Fields{
			"rules": watchlist.GetRules(),
		}).Debug("Starting with the pre-configured INT watchlist")
	}

	itr.reportHandler.SetINTWatchlist(watchlist.GetRules())
}

func (itr *IntHostReporter) loadBPFProgram(ifName string) error {
	loaderProg := "tc"
	ingressArgs := []string{"filter", "replace", "dev", ifName, "ingress",
		"prio", "1", "handle", "3", "bpf", "da", "obj", "/opt/out.o",
		"sec", "classifier/ingress",
	}
	egressArgs := []string{"filter", "replace", "dev", ifName, "egress",
		"prio", "1", "handle", "3", "bpf", "da", "obj", "/opt/out.o",
		"sec", "classifier/egress",
	}

	cmd := exec.Command(loaderProg, ingressArgs...)
	_, err := cmd.Output()
	if err != nil {
		return err
	}

	cmd = exec.Command(loaderProg, egressArgs...)
	_, err = cmd.Output()
	if err != nil {
		return err
	}

	return nil
}

func (itr *IntHostReporter) attachINTProgramsAtStartup() {
	links, _ := netlink.LinkList()
	for _, link := range links {
		if link.Attrs().Name == *DataInterface ||
			(strings.Contains(link.Attrs().Name, "lxc") && link.Attrs().Name != "lxc_health") {
			log.Debugf("Trying to load BPF program to %s", link.Attrs().Name)
			err := itr.loadBPFProgram(link.Attrs().Name)
			if err != nil {
				log.Errorf("Failed to load BPF program to %s: %v", link.Attrs().Name, err.Error())
			} else {
				log.Debugf("Successfully loaded BPF program to %s", link.Attrs().Name)
			}
		}
	}
}

func interfaceHasINTProgram(link netlink.Link, handle uint32) bool {
	filters, err := netlink.FilterList(link, handle)
	if err != nil {
		log.Error("failed to get filter list for link %v: %v", link.Attrs().Name, err.Error())
		return false
	}
	for _, f := range filters {
		if f.Attrs().Handle == INTProgramHandle {
			return true
		}
	}

	return false
}

// This function will (re-)load INT programs in two cases:
// 1) when a new container's interface is created
// 2) when a CNI will clear INT programs from a container's interface
func (itr *IntHostReporter) reloadINTProgramsIfNeeded() {
	for {
		links, _ := netlink.LinkList()
		for _, link := range links {
			if link.Attrs().Name == *DataInterface ||
				(strings.Contains(link.Attrs().Name, "lxc") && link.Attrs().Name != "lxc_health") {
				if !interfaceHasINTProgram(link, netlink.HANDLE_MIN_INGRESS) ||
					!interfaceHasINTProgram(link, netlink.HANDLE_MIN_EGRESS) {
					log.Debugf("Re-loading INT eBPF program to interface %v", link.Attrs().Name)
					err := itr.loadBPFProgram(link.Attrs().Name)
					if err != nil {
						log.Errorf("Failed to load BPF program to %s: %v", link.Attrs().Name, err.Error())
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
}

func (itr *IntHostReporter) Start() error {
	dataPlaneInterfaceCtx, cancel := context.WithCancel(itr.ctx)
	itr.perfReaderCancel = cancel

	itr.attachINTProgramsAtStartup()
	go itr.reloadINTProgramsIfNeeded()

	err := itr.dataPlaneInterface.Init()
	if err != nil {
		return err
	}

	err = itr.reportHandler.Start()
	if err != nil {
		return err
	}

	go itr.dataPlaneInterface.DetectPacketDrops()

	// Blocking
	err = itr.dataPlaneInterface.Start(dataPlaneInterfaceCtx)
	if err != nil {
		return err
	}

	return nil
}
