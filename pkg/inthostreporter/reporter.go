package inthostreporter

import (
	"context"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
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
	intWatchlist := watchlist.NewINTWatchlist()
	itr.reportHandler = NewReportHandler(itr.dataPlaneInterface, intWatchlist)
	return itr
}

func (itr *IntHostReporter) Start() error {
	dataPlaneInterfaceCtx, cancel := context.WithCancel(itr.ctx)
	itr.perfReaderCancel = cancel
	err := itr.reportHandler.Start()
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