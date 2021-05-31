package inthostreporter

import "context"

type IntHostReporter struct {
	ctx              context.Context
	perfReaderCancel context.CancelFunc

	dataPlaneInterface *dataPlaneInterface
}

func NewIntHostReporter() *IntHostReporter {
	itr := &IntHostReporter{}
	itr.ctx = context.Background()
	itr.dataPlaneInterface = NewDataPlaneInterface()
	return itr
}

func (itr *IntHostReporter) Start() error {
	dataPlaneInterfaceCtx, cancel := context.WithCancel(itr.ctx)
	itr.perfReaderCancel = cancel

	// Blocking
	err := itr.dataPlaneInterface.Start(dataPlaneInterfaceCtx)
	if err != nil {
		return err
	}

	return nil
}