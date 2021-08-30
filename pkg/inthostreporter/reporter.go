package inthostreporter

import (
	"context"
	"fmt"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"os/exec"
	"strings"
	"time"
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

func (itr *IntHostReporter) configureInterfacesAtStartup() {
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

func (itr *IntHostReporter) listenAndConfigureInterfaces(updates chan netlink.LinkUpdate) {
	for update := range updates {
		if update.IfInfomsg.Flags&unix.IFF_RUNNING != 0 && update.IfInfomsg.Flags&unix.IFF_UP != 0 &&
			(strings.Contains(update.Link.Attrs().Name, "lxc") && update.Link.Attrs().Name != "lxc_health") {
			retries := 3
			for i := 0; i < retries; i++ {
				log.Debugf("Trying to load BPF program to %s, retries_left=%d", update.Link.Attrs().Name, retries-i)
				err := itr.loadBPFProgram(update.Link.Attrs().Name)
				if err != nil {
					log.Errorf("Failed to load BPF program to %s: %v", update.Link.Attrs().Name, err.Error())
					time.Sleep(time.Second+1)
					continue
				}
				log.Debugf("Successfully loaded BPF program to %s", update.Link.Attrs().Name)
				break
			}
		}
	}
}

func (itr *IntHostReporter) Start() error {
	dataPlaneInterfaceCtx, cancel := context.WithCancel(itr.ctx)
	itr.perfReaderCancel = cancel

	itr.configureInterfacesAtStartup()

	updates := make(chan netlink.LinkUpdate, 100)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(updates, done); err != nil {
		return fmt.Errorf("failed to subscribe to link updates: %v", err)
	}

	go itr.listenAndConfigureInterfaces(updates)

	err := itr.dataPlaneInterface.Init()
	if err != nil {
		return err
	}

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
