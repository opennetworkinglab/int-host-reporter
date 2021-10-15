// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket/layers"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/watchlist"
	log "github.com/sirupsen/logrus"
	"math/bits"
	"net"
	"os"
	"time"
)

type DataPlaneInterface struct {
	eventsChannel chan PacketMetadata

	watchlistMapProtoSrcAddr *ebpf.Map
	watchlistMapDstAddr      *ebpf.Map

	sharedMap        *ebpf.Map

	ingressSeqNumMap *ebpf.Map
	egressSeqNumMap  *ebpf.Map

	perfEventArray  *ebpf.Map
	dataPlaneReader *perf.Reader
}

type SharedMapKey struct {
	PacketIdentifier uint64
	FlowHash         uint32
	Padding          uint32
}

type SharedMapValue struct {
	IngressTimestamp uint64
	IngressPort      uint32
	PreNATIPDest     uint32
	PreNATIPSource   uint32
	PreNATProto      uint16
	Padding0         uint16
	PreNATSourcePort uint16
	PreNATDestPort   uint16
	SeqNo            uint16
	SeenByUserspace  uint16
}

type IngressSeqNumValue struct {
	IngressTimestamp uint64
	IngressPort      uint32
	SeqNum           uint32
	SrcIP            uint32
	DstIP            uint32
	IPProtocol       uint32
	SourcePort       uint16
	DestPort         uint16
}

func (key SharedMapKey) String() string {
	return fmt.Sprintf("SharedMapKey={packet-identifier=%v, flow_hash=%x}",
		key.PacketIdentifier, key.FlowHash)
}

func (value SharedMapValue) String() string {
	return fmt.Sprintf("SharedMapValue={ig_timestamp=%v, ig_port=%v, pre-nat-ip-dst=%v," +
		"pre-nat-ip-src=%v, pre-nat-source-port=%v, pre-nat-dest-port=%v, seen-by-userspace=%v}",
		value.IngressTimestamp, value.IngressPort,
		common.ToNetIP(value.PreNATIPDest).String(),
		common.ToNetIP(value.PreNATIPSource).String(),
		bits.ReverseBytes16(value.PreNATSourcePort),
		bits.ReverseBytes16(value.PreNATDestPort), value.SeenByUserspace)
}

func init() {
	// clear SHARED_MAP; ignore err
	os.Remove(common.DefaultMapRoot + "/" + common.DefaultMapPrefix + "/" + common.INTSharedMap)
}

func NewDataPlaneInterface() *DataPlaneInterface {
	return &DataPlaneInterface{}
}

func (d *DataPlaneInterface) SetEventChannel(ch chan PacketMetadata) {
	d.eventsChannel = ch
}

func (d *DataPlaneInterface) Init() error {
	layers.RegisterUDPPortLayerType(8472, layers.LayerTypeVXLAN)

	commonPath := common.DefaultMapRoot + "/" + common.DefaultMapPrefix
	path := commonPath + "/" + common.INTSharedMap
	sharedMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	d.sharedMap = sharedMap

	path = commonPath + "/" + common.INTEventsMap
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
		case err != nil:
			{
				log.Warn("Error received while reading from perf buffer")
				// TODO (tomasz): log error here
				continue
			}
		}
		d.processPerfRecord(record)
	}
}

func (d *DataPlaneInterface) DetectPacketDrops() {
	log.Debug("Starting packet drop detection process..")
	for {
		var key SharedMapKey
		var value SharedMapValue
		iter := d.sharedMap.Iterate()
		for iter.Next(&key, &value) {
			err := d.sharedMap.Lookup(&key, &value)
			if err != nil {
				log.Debugf("failed to lookup from shared map: %v", err)
				continue
			}

			if value.SeenByUserspace == 1 {
				pktMd := PacketMetadata{
					DataPlaneReport: &DataPlaneReport{
						Type:                  DropReport,
						Reason:                common.DropReasonUnknown,
						PreNATSourceIP:        common.ToNetIP(value.PreNATIPSource),
						PreNATDestinationIP:   common.ToNetIP(value.PreNATIPDest),
						PreNATSourcePort:      bits.ReverseBytes16(value.PreNATSourcePort),
						PreNATDestinationPort: bits.ReverseBytes16(value.PreNATDestPort),
						IngressPort:           value.IngressPort,
						EgressPort:            0,
						IngressTimestamp:      value.IngressTimestamp,
						EgressTimestamp:       0,
					},
					EncapMode: "",
					DstAddr:   net.IPv4zero,
					SrcAddr:   net.IPv4zero,
					Protocol:  uint8(value.PreNATProto),
					DstPort:   0,
					SrcPort:   0,
				}

				d.eventsChannel <- pktMd

				// this is the second time we see this entry,
				// so it's very likely that this packet haven't reached any egress program.
				// Therefore, we can delete it from map and report a potential packet drop.
				err = d.sharedMap.Delete(&key)
				if err != nil {
					log.Debugf("failed to delete key %v from shared map: %v", key, err)
				}
				log.WithFields(log.Fields{
					"key": key,
					"value": value,
				}).Trace("Deleted entry from map")
				continue
			}

			value.SeenByUserspace = 1

			err = d.sharedMap.Put(&key, &value)
			if err != nil {
				log.Debugf("Failed to set seen-by-userspace flag")
				continue
			}

			log.WithFields(log.Fields{
				"key": key,
				"value": value,
			}).Trace("seen-by-userspace flag set for entry")
		}
		time.Sleep(time.Second)
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
		protocol  uint32
		saddr     uint32
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
		daddr     uint32
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
		"CPU":            record.CPU,
		"HasLostSamples": record.LostSamples > 0,
		"DataSize":       len(record.RawSample),
	}).Trace("perf event read")

	if record.LostSamples > 0 {
		log.WithFields(log.Fields{
			"lost": record.LostSamples,
		}).Warn("Records has been lost because ring buffer is full, consider to increase size?")
		return
	}

	event := Event{
		Data: record.RawSample,
		CPU:  record.CPU,
	}
	pktMd := event.Parse()
	select {
	case d.eventsChannel <- *pktMd:
	default:
		log.Warn("Dropped event because events channel is full or closed")
	}
}
