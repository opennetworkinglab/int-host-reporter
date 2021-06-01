package inthostreporter

import (
	"context"
)

type IntHostReporter struct {
	ctx              context.Context
	perfReaderCancel context.CancelFunc

	reportHandler      *ReportHandler
	dataPlaneInterface *dataPlaneInterface
}

func NewIntHostReporter() *IntHostReporter {
	itr := &IntHostReporter{}
	itr.ctx = context.Background()
	itr.dataPlaneInterface = NewDataPlaneInterface()
	itr.reportHandler = NewReportHandler(itr.dataPlaneInterface)
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