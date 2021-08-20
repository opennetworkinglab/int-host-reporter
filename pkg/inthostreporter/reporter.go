package inthostreporter

import (
	"strings"
	"os/exec"
	"context"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type IntHostReporter struct {
	ctx              context.Context
	perfReaderCancel context.CancelFunc

	reportHandler      *ReportHandler
	dataPlaneInterface *dataplane.DataPlaneInterface
}

func NewIntHostReporter() *IntHostReporter {
	itr := &IntHostReporter{}
	itr.ctx = context.Background()
	itr.dataPlaneInterface = dataplane.NewDataPlaneInterface()
	itr.reportHandler = NewReportHandler(itr.dataPlaneInterface)
	return itr
}

func (itr *IntHostReporter) initWatchlist(watchlist *watchlist.INTWatchlist) error {
	for _, rule := range watchlist.GetRules() {
		err := itr.dataPlaneInterface.UpdateWatchlist(rule.GetProtocol(), rule.GetSrcAddr(), rule.GetDstAddr(), watchlist.GetRules())
		if err != nil {
			return err
		}
	}

	if len(watchlist.GetRules()) > 0 {
		log.WithFields(log.Fields{
			"rules": watchlist.GetRules(),
		}).Debug("Starting with the pre-configured INT watchlist")
	}

	return nil
}

func (itr *IntHostReporter) loadBPFProgram(ifName string) {
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
		log.Error(err)
	}

	cmd = exec.Command(loaderProg, egressArgs...)
	stdout, err := cmd.Output()
	log.Debug(stdout)
	if err != nil {
		log.Error(err.Error())
	}
}

func (itr *IntHostReporter) configureInterfacesAtStartup() {
	links, _ := netlink.LinkList()
	for _, link := range links {
		log.Debug(link.Attrs().Name)
		if link.Attrs().Name == *DataInterface ||
			(strings.Contains(link.Attrs().Name, "lxc") && link.Attrs().Name != "lxc_health") {
			log.Debug("About to configure ", link.Attrs().Name)
			itr.loadBPFProgram(link.Attrs().Name)
		}
	}
}

func (itr *IntHostReporter) listenAndConfigureInterfaces() {
	ch := make(chan netlink.LinkUpdate, 100)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		log.Error("Failed to subscribe to link updates")
		return
	}

	for update := range ch {
		log.Debug("Received update for ", update.Link.Attrs().Name, ", flags ", update.IfInfomsg.Flags)
		// FIXME: fix problem when loading the BPF program to a new interface
		//if update.IfInfomsg.Flags&unix.IFF_UP != 0 &&
		//	(strings.Contains(update.Link.Attrs().Name, "lxc") && update.Link.Attrs().Name != "lxc_health") {
		//	itr.loadBPFProgram(update.Link.Attrs().Name)
		//}
	}
}

func (itr *IntHostReporter) Start(watchlist *watchlist.INTWatchlist) error {
	dataPlaneInterfaceCtx, cancel := context.WithCancel(itr.ctx)
	itr.perfReaderCancel = cancel

	itr.configureInterfacesAtStartup()
	go itr.listenAndConfigureInterfaces()

	err := itr.dataPlaneInterface.Init()
	if err != nil {
		return err
	}

	//err = itr.initWatchlist(watchlist)
	//if err != nil {
	//	log.Fatalf("Failed to initialize the INT watchlist: %v", err)
	//}

	err = itr.reportHandler.Start()
	if err != nil {
		return err
	}

	// Blocking
	err = itr.dataPlaneInterface.Start(dataPlaneInterfaceCtx)
	if err != nil {
		return err
	}

	return nil
}