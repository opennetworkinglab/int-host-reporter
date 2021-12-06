// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package inthostreporter

import (
	"context"
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/loader"
	"github.com/opennetworkinglab/int-host-reporter/pkg/service"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const (
	INTProgramHandle = 3
)

type IntHostReporter struct {
	ctx        context.Context
	cancelFunc context.CancelFunc

	restService        *http.Server
	reportHandler      *ReportHandler
	dataPlaneInterface *dataplane.EBPFDatapathInterface

	signals chan os.Signal
}

func NewIntHostReporter(watchlist *watchlist.INTWatchlist) *IntHostReporter {
	itr := &IntHostReporter{}
	itr.ctx = context.Background()
	itr.dataPlaneInterface = dataplane.NewDataPlaneInterface()
	itr.reportHandler = NewReportHandler(itr.dataPlaneInterface)
	itr.signals = make(chan os.Signal, 1)
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
	}

	log.Debugf("replacing qdisc for %s succeeded", ifName)
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

func (itr *IntHostReporter) removeBPFProgram(ifName string) error {
	loaderProg := "tc"
	baseCmd := []string{"filter", "del", "dev", ifName}
	clearIngressCmd := append(baseCmd, "ingress")
	clearEgressCmd := append(baseCmd, "egress")

	clearIngressCmd = append(clearIngressCmd, []string{"prio", "1", "handle", "3", "bpf"}...)
	clearEgressCmd = append(clearEgressCmd, []string{"prio", "1", "handle", "3", "bpf"}...)

	cmd := exec.Command(loaderProg, clearIngressCmd...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Debugf("failed to remove ingress filter from interface %s: %v",
			ifName, string(out))
		return err
	}

	cmd = exec.Command(loaderProg, clearEgressCmd...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		log.Debugf("failed to remove egress filter from interface %s: %v",
			ifName, string(out))
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
		if link.Attrs().Name == *common.DataInterface || common.IsInterfaceManagedByCNI(link.Attrs().Name) {
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

func (itr *IntHostReporter) clearINTPrograms() (err error) {
	links, _ := netlink.LinkList()
	for _, link := range links {
		if link.Attrs().Name == *common.DataInterface || common.IsInterfaceManagedByCNI(link.Attrs().Name) {
			log.Debugf("Clearing BPF program from %s", link.Attrs().Name)
			err = itr.removeBPFProgram(link.Attrs().Name)
		}
	}

	if err == nil {
		log.Info("Successfully removed BPF programs from all interfaces.")
	}
	return err
}

func interfaceHasINTProgram(link netlink.Link, handle uint32) bool {
	filters, err := netlink.FilterList(link, handle)
	if err != nil {
		log.Errorf("failed to get filter list for link %v: %v", link.Attrs().Name, err.Error())
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
func (itr *IntHostReporter) reloadINTProgramsIfNeeded(stopCtx context.Context) {
	for {
		select {
		case <-stopCtx.Done():
			return
		default:
			{
				links, _ := netlink.LinkList()
				for _, link := range links {
					if link.Attrs().Name == *common.DataInterface ||
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
	}
}

func (itr *IntHostReporter) Start() error {
	// Setup signal handler.
	signal.Notify(itr.signals, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(itr.ctx)
	itr.cancelFunc = cancel

	itr.restService = service.New(":4048")
	log.Info("Starting REST service listening on :4048")
	go itr.restService.ListenAndServe()

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

	go itr.reloadINTProgramsIfNeeded(ctx)
	go itr.dataPlaneInterface.DetectPacketDrops(ctx)

	go itr.HandleSignals()

	// Blocking
	err = itr.dataPlaneInterface.Start(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (itr *IntHostReporter) Stop() (err error) {
	itr.cancelFunc()
	itr.restService.Close()
	itr.reportHandler.Stop()
	err = itr.clearINTPrograms()
	itr.dataPlaneInterface.Stop()
	close(itr.signals)
	return
}

func (itr *IntHostReporter) HandleSignals() {
	for {
		sig, ok := <-itr.signals
		if !ok {
			return
		}
		log.Debugf("Got signal %v", sig)
		if err := itr.Stop(); err != nil {
			log.Fatal("Error stopping INT Host Reporter:", err)
		}
	}
}
