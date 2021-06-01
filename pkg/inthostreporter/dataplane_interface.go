package inthostreporter

import (
	"context"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"
)

type dataPlaneInterface struct {
	eventsChannel   chan dataPlaneEvent

	perfEventArray  *ebpf.Map
	dataPlaneReader *perf.Reader
}

func NewDataPlaneInterface() *dataPlaneInterface {
	return &dataPlaneInterface{}
}

func (d *dataPlaneInterface) SetEventChannel(ch chan dataPlaneEvent) {
	d.eventsChannel = ch
}

func (d *dataPlaneInterface) Start(stopCtx context.Context) error {
	path := DefaultMapRoot + "/" + DefaultMapPrefix + "/" + CalicoPerfEventArray
	eventsMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	d.perfEventArray = eventsMap

	// TODO (tomasz): make it configurable
	bufferSize := 100
	events, err := perf.NewReader(d.perfEventArray, bufferSize)
	if err != nil {
		return err
	}
	defer func() {
		events.Close()
		d.dataPlaneReader = nil
	}()
	d.dataPlaneReader = events
	log.Infof("Listening for perf events from %s", d.perfEventArray.String())
	// TODO (tomasz): break loop with cancel ctx
	for {
		record, err := events.Read()
		switch {
		case err != nil: {
			log.Warn("Error received while reading from perf buffer")
			// TODO (tomasz): log error here
			continue
		}
		}
		d.processPerfRecord(record)
	}
}

func (d *dataPlaneInterface) processPerfRecord(record perf.Record) {
	log.WithFields(log.Fields{
		"CPU": record.CPU,
		"HasLostSamples": record.LostSamples > 0,
		"DataSize": len(record.RawSample),
	}).Trace("perf event read")

	if record.LostSamples > 0 {
		log.WithFields(log.Fields{
			"lost": record.LostSamples,
		}).Warn("Records has been lost because ring buffer is full, consider to increase size?")
	}

	event := dataPlaneEvent{
		Data: record.RawSample,
		CPU: record.CPU,
	}
	select {
	case d.eventsChannel <- event:
	default:
		log.Warn("Dropped event because events channel is full or closed")
	}
}

