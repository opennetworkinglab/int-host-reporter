package inthostreporter

import (
	"context"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
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

func (itr *IntHostReporter) Start(watchlist *watchlist.INTWatchlist) error {
	dataPlaneInterfaceCtx, cancel := context.WithCancel(itr.ctx)
	itr.perfReaderCancel = cancel

	err := itr.dataPlaneInterface.Init()
	if err != nil {
		return err
	}

	err = itr.initWatchlist(watchlist)
	if err != nil {
		log.Fatalf("Failed to initialize the INT watchlist: %v", err)
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