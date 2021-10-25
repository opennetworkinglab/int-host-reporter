// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package inthostreporter

import (
	"context"
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/loader"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"os/exec"
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

func tcQdiscExists(ifName string) bool {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return false
	}

	qdiscs, _ := netlink.QdiscList(link)
	for _, qdisc := range qdiscs {
		if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT {
			return true
		}
	}

	return false
}

func addTcQdisc(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err = netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("replacing qdisc for %s failed: %s", ifName, err)
	} else {
		log.Debugf("replacing qdisc for %s succeeded", ifName)
	}

	return nil
}

func (itr *IntHostReporter) loadBPFProgram(ifName string) error {
	if !tcQdiscExists(ifName) {
		err := addTcQdisc(ifName)
		if err != nil {
			log.Debugf("failed to add clsact qdisc for %v: %v", ifName, err)
			return err
		}
	}

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
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("ingress filter replace failed: %v", string(out))
		return err
	}

	cmd = exec.Command(loaderProg, egressArgs...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Debugf("egress filter replace failed: %v", string(out))
		return err
	}

	return nil
}

func (itr *IntHostReporter) attachINTProgramsAtStartup() error {
	options := loader.CompileOptions{}
	if log.GetLevel() == log.TraceLevel || log.GetLevel() == log.DebugLevel {
		options.Debug = true
	}
	err := loader.CompileDatapath(options)
	if err != nil {
		return fmt.Errorf("failed to compile datapath: %v", err)
	}

	noProgramsAttached := true
	links, _ := netlink.LinkList()
	for _, link := range links {
		if link.Attrs().Name == *DataInterface || common.IsInterfaceManagedByCNI(link.Attrs().Name) {
			log.Debugf("Trying to load BPF program to %s", link.Attrs().Name)
			err = itr.loadBPFProgram(link.Attrs().Name)
			if err != nil {
				log.Errorf("Failed to load BPF program to %s: %v", link.Attrs().Name, err)
			} else {
				noProgramsAttached = false
				log.Debugf("Successfully loaded BPF program to %s", link.Attrs().Name)
			}
		}
	}

	if noProgramsAttached {
		return fmt.Errorf("no BPF program has been attached, verify if data interface is configured")
	}

	return nil
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
				common.IsInterfaceManagedByCNI(link.Attrs().Name) {
				if !interfaceHasINTProgram(link, netlink.HANDLE_MIN_INGRESS) ||
					!interfaceHasINTProgram(link, netlink.HANDLE_MIN_EGRESS) {
					log.Debugf("Re-loading INT eBPF program to interface %v", link.Attrs().Name)
					err := itr.loadBPFProgram(link.Attrs().Name)
					if err != nil {
						log.Errorf("Failed to load BPF program to %s: %v", link.Attrs().Name, err)
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

	err := itr.attachINTProgramsAtStartup()
	if err != nil {
		return err
	}

	err = itr.dataPlaneInterface.Init()
	if err != nil {
		return err
	}

	err = itr.reportHandler.Start()
	if err != nil {
		return err
	}

	go itr.reloadINTProgramsIfNeeded()
	go itr.dataPlaneInterface.DetectPacketDrops()

	// Blocking
	err = itr.dataPlaneInterface.Start(dataPlaneInterfaceCtx)
	if err != nil {
		return err
	}

	return nil
}
