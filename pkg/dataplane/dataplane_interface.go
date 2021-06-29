package dataplane

import (
	"context"
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	log "github.com/sirupsen/logrus"
	"net"
)

type DataPlaneInterface struct {
	eventsChannel   chan Event

	watchlistMap    *ebpf.Map
	perfEventArray  *ebpf.Map
	dataPlaneReader *perf.Reader
}

func NewDataPlaneInterface() *DataPlaneInterface {
	return &DataPlaneInterface{}
}

func (d *DataPlaneInterface) SetEventChannel(ch chan Event) {
	d.eventsChannel = ch
}

func (d *DataPlaneInterface) Init() error {
	commonPath := common.DefaultMapRoot + "/" + common.DefaultMapPrefix
	path := commonPath + "/" + common.CalicoWatchlistMap
	watchlistMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	d.watchlistMap = watchlistMap

	path = commonPath + "/" + common.CalicoPerfEventArray
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
	d.dataPlaneReader = events
	return nil
}

func (d *DataPlaneInterface) Start(stopCtx context.Context) error {
	defer func() {
		d.dataPlaneReader.Close()
		d.dataPlaneReader = nil
	}()
	log.Infof("Listening for perf events from %s", d.perfEventArray.String())
	// TODO (tomasz): break loop with cancel ctx
	for {
		record, err := d.dataPlaneReader.Read()
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

func (d *DataPlaneInterface) UpdateWatchlist(protocol uint8, srcAddr net.IP, dstAddr net.IP) error {
	key := struct {
		protocol uint32
		saddr uint32
		daddr uint32
	}{}
	key.protocol = uint32(protocol)
	key.saddr = binary.LittleEndian.Uint32(srcAddr.To4())
	key.daddr = binary.LittleEndian.Uint32(dstAddr.To4())

	var dummyValue uint8 = 0
	err := d.watchlistMap.Update(key, dummyValue, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("failed to insert watchlist entry: %v", err)
		return err
	}
	return nil
}

func (d *DataPlaneInterface) processPerfRecord(record perf.Record) {
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

	event := Event{
		Data: record.RawSample,
		CPU: record.CPU,
	}
	select {
	case d.eventsChannel <- event:
	default:
		log.Warn("Dropped event because events channel is full or closed")
	}
}

