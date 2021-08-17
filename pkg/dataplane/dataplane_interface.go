package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"net"
)

type DataPlaneInterface struct {
	eventsChannel   chan Event

	watchlistMapProtoSrcAddr    *ebpf.Map
	watchlistMapDstAddr 		*ebpf.Map

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
	path := commonPath + "/" + common.CalicoWatchlistMapProtoSrcAddr
	watchlistMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	d.watchlistMapProtoSrcAddr = watchlistMap

	path = commonPath + "/" + common.CalicoWatchlistMapDstAddr
	watchlistMap, err = ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	d.watchlistMapDstAddr = watchlistMap

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

func calculateBitVectorForProtoSrcAddrMap(protocol uint32, srcAddr net.IPNet, allRules []watchlist.INTWatchlistRule) uint64 {
	log.Debugf("Calculating BitVector for Protocol=%v, SrcAddr=%v", protocol, srcAddr)
	var bitvector uint64 = 0
	for idx, rule := range allRules {
		if protocol == uint32(rule.GetProtocol()) &&
			(rule.GetSrcAddr().IP.Equal(srcAddr.IP) && bytes.Equal(rule.GetSrcAddr().Mask, srcAddr.Mask)) {
			bitvector = bitvector | (1 << idx)
		}
	}
	return bitvector
}

func calculateBitVectorForDstAddr(dstAddr net.IPNet, allRules []watchlist.INTWatchlistRule) uint64 {
	log.Debugf("Calculating BitVector for DstAddr=%v", dstAddr)
	var bitvector uint64 = 0
	for idx, rule := range allRules {
		if rule.GetDstAddr().IP.Equal(dstAddr.IP) && bytes.Equal(rule.GetDstAddr().Mask, dstAddr.Mask) {
			bitvector = bitvector | (1 << idx)
		}
	}
	return bitvector
}

func (d *DataPlaneInterface) UpdateWatchlist(protocol uint8, srcAddr net.IPNet, dstAddr net.IPNet, allRules []watchlist.INTWatchlistRule) error {
	keyProtoSrcAddr := struct {
		prefixlen uint32
		protocol uint32
		saddr uint32
	}{}
	ones, _ := srcAddr.Mask.Size()
	keyProtoSrcAddr.prefixlen = 32 + uint32(ones)
	keyProtoSrcAddr.protocol = uint32(protocol)
	keyProtoSrcAddr.saddr = binary.LittleEndian.Uint32(srcAddr.IP.To4())

	value := calculateBitVectorForProtoSrcAddrMap(uint32(protocol), srcAddr, allRules)
	log.Debugf("Bitvector for protoSrcAddr: %x", value)
	err := d.watchlistMapProtoSrcAddr.Update(keyProtoSrcAddr, value, ebpf.UpdateAny)
	if err != nil {
		log.Errorf("failed to insert watchlist entry: %v", err)
		return err
	}

	keyDstAddr := struct {
		prefixlen uint32
		daddr uint32
	}{}
	ones, _ = dstAddr.Mask.Size()
	keyDstAddr.prefixlen = uint32(ones)
	keyDstAddr.daddr = binary.LittleEndian.Uint32(dstAddr.IP.To4())
	value = calculateBitVectorForDstAddr(dstAddr, allRules)
	log.Debugf("Bitvector for DstAddr: %x", value)
	err = d.watchlistMapDstAddr.Update(keyDstAddr, value, ebpf.UpdateAny)
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
		return
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

