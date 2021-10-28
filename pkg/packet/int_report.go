// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package packet

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/opennetworkinglab/int-host-reporter/pkg/common"
	"github.com/opennetworkinglab/int-host-reporter/pkg/dataplane"
	log "github.com/sirupsen/logrus"
	"net"
)

const (
	NProtoEthernet             = 0
	NProtoTelemetryDrop        = 1
	NProtoTelemetrySwitchLocal = 2

	SizeINTFixedHeader      = 12
	SizeINTDropReportHeader = 12
	SizeINTFlowReportHeader = 16
	// SizeEthernetIPv4UDPVXLAN specifies the total length of Ethernet, IPv4, UDP and VXLAN headers.
	// Used to strip out the outer headers.
	SizeEthernetIPv4UDPVXLAN = 50

	OffsetDestinationIPVXLAN     = 80
	OffsetDestinationPortVXLAN   = 86
	OffsetDestinationIPNoEncap   = 30
	OffsetDestinationPortNoEncap = 36
)

var (
	LayerTypeINTReportFixedHeader = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{
		Name: "INTReportFixedHeader",
		// we won't be decoding INT Report Fixed Header as we only send reports.
		Decoder: gopacket.DecodeUnknown,
	})
	LayerTypeINTFlowReportHeader = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{
		Name: "INTFlowReport",
		// we won't be decoding INT Flow Report as we only send reports.
		Decoder: gopacket.DecodeUnknown,
	})
	LayerTypeINTDropReportHeader = gopacket.RegisterLayerType(1003, gopacket.LayerTypeMetadata{
		Name: "INTDropReport",
		// we won't be decoding INT Drop Report as we only send reports.
		Decoder: gopacket.DecodeUnknown,
	})
)

type INTReportFixedHeader struct {
	layers.BaseLayer
	Version uint8
	NProto  uint8
	// 1-bit field
	Dropped bool
	// 1-bit field
	CongestedQueueAssociation bool
	// 1-bit field
	TrackedFlowAssociation bool
	// 6-bit field
	HwID             uint8
	SeqNo            uint32
	IngressTimestamp uint32
}

type INTCommonReportHeader struct {
	layers.BaseLayer
	SwitchID    uint32
	IngressPort uint16
	EgressPort  uint16
	QueueID     uint8
}

type INTDropReportHeader struct {
	layers.BaseLayer
	INTCommonReportHeader
	DropReason uint8
}

type INTLocalReportHeader struct {
	layers.BaseLayer
	INTCommonReportHeader
	// 24-bit field
	QueueOccupancy  uint32
	EgressTimestamp uint32
}

func (f INTReportFixedHeader) String() string {
	return fmt.Sprintf("NProto=%v, HwID=%v, SeqNo=%v, IngressTimestamp=%v",
		f.NProto, f.HwID, f.SeqNo, f.IngressTimestamp)
}

func (f INTReportFixedHeader) LayerType() gopacket.LayerType {
	return LayerTypeINTReportFixedHeader
}

func (f INTReportFixedHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(SizeINTFixedHeader)
	if err != nil {
		return err
	}

	bytes[0] = (f.Version << 4) | f.NProto
	if f.Dropped {
		bytes[1] |= 1 << 7
	}
	if f.CongestedQueueAssociation {
		bytes[1] |= 1 << 6
	}
	if f.TrackedFlowAssociation {
		bytes[1] |= 1 << 5
	}

	bytes[2] = byte(0)
	bytes[3] = f.HwID &^ (3 << 6)
	binary.BigEndian.PutUint32(bytes[4:], f.SeqNo)
	binary.BigEndian.PutUint32(bytes[8:], f.IngressTimestamp)

	return nil
}

func (l INTLocalReportHeader) String() string {
	return fmt.Sprintf("SwitchID=%v, IngressPort=%v, EgressPort=%v, EgressTimestamp=%v",
		l.SwitchID, l.IngressPort, l.EgressPort, l.EgressTimestamp)
}

func (l INTLocalReportHeader) LayerType() gopacket.LayerType {
	return LayerTypeINTFlowReportHeader
}

func (l INTLocalReportHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(SizeINTFlowReportHeader)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(bytes[0:], l.SwitchID)
	binary.BigEndian.PutUint16(bytes[4:], l.IngressPort)
	binary.BigEndian.PutUint16(bytes[6:], l.EgressPort)
	bytes[8] = l.QueueID

	// End host doesn't have any queues. Zero-initialize the fields related to queues.
	copy(bytes[9:12], []byte{0, 0, 0})

	binary.BigEndian.PutUint32(bytes[12:], l.EgressTimestamp)

	return nil
}

func (d INTDropReportHeader) String() string {
	return fmt.Sprintf("SwitchID=%v, IngressPort=%v, EgressPort=%v, DropReason=%v",
		d.SwitchID, d.IngressPort, d.EgressPort, d.DropReason)
}

func (d INTDropReportHeader) LayerType() gopacket.LayerType {
	return LayerTypeINTDropReportHeader
}

func (d INTDropReportHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(SizeINTDropReportHeader)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(bytes[0:], d.SwitchID)
	binary.BigEndian.PutUint16(bytes[4:], d.IngressPort)
	binary.BigEndian.PutUint16(bytes[6:], d.EgressPort)
	bytes[8] = d.QueueID
	bytes[9] = d.DropReason

	return nil
}

func dropReasonConvertFromDatapathToINT(datapathCode uint8) uint8 {
	switch datapathCode {
	case 0:
		// unknown reason has the same code.
		return datapathCode
	case 207:
		return common.DropReasonChecksumFail
	case 239:
		return common.DropReasonEncapFail
	case 223:
		return common.DropReasonDecapFail
	case 235:
		return common.DropReasonIPOptions
	case 236:
		return common.DropReasonIPIHLInvalid
	case 237:
		return common.DropReasonUnauthSource
	case 240:
		return common.DropReasonIPTTLZero
	case 241:
		return common.DropReasonACLDeny
	default:
		log.WithFields(log.Fields{
			"code": datapathCode,
		}).Warning("unknown drop reason reported by datapath. Returning unknown reason.")
		return common.DropReasonUnknown
	}
}

func getINTFixedHeader(pktMd *dataplane.PacketMetadata, hwID uint8, seqNo uint32) INTReportFixedHeader {
	return INTReportFixedHeader{
		Version:                   0,
		NProto:                    0,
		Dropped:                   false,
		CongestedQueueAssociation: false,
		TrackedFlowAssociation:    false,
		HwID:                      hwID,
		SeqNo:                     seqNo,
		IngressTimestamp:          uint32(pktMd.DataPlaneReport.IngressTimestamp),
	}
}

func getINTCommonHeader(pktMd *dataplane.PacketMetadata, switchID uint32) INTCommonReportHeader {
	return INTCommonReportHeader{
		SwitchID:    switchID,
		IngressPort: uint16(pktMd.DataPlaneReport.IngressPort),
		EgressPort:  uint16(pktMd.DataPlaneReport.EgressPort),
		QueueID:     0,
	}
}

func constructPayloadFromFiveTuple(srcAddr, dstAddr net.IP, protocol uint8, srcPort, dstPort uint16) ([]byte, error) {
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		// dummy Eth addresses; INT collector should not care about L2
		SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := &layers.IPv4{
		Version: 4,
		TTL: 64,
		Protocol:   layers.IPProtocol(protocol),
		SrcIP:      srcAddr,
		DstIP:      dstAddr,
	}

	var l4 gopacket.SerializableLayer
	switch protocol {
	case 6:
		udp := &layers.UDP{
			SrcPort:   layers.UDPPort(srcPort),
			DstPort:   layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ipv4)
		l4 = udp
	case 17:
		tcp := &layers.TCP{
			SrcPort:    layers.TCPPort(srcPort),
			DstPort:    layers.TCPPort(dstPort),
		}
		tcp.SetNetworkLayerForChecksum(ipv4)
		l4 = tcp
	default:
		return []byte{}, fmt.Errorf("protocol not supported")
	}

	dummyPayload := gopacket.Payload{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	err := gopacket.SerializeLayers(buf, opts, &eth, ipv4, l4, &dummyPayload)
	if err != nil {
		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func getINTPayload(pktMd *dataplane.PacketMetadata) gopacket.Payload {
	if len(pktMd.DataPlaneReport.Payload) == 0 {
		payload, err := constructPayloadFromFiveTuple(pktMd.SrcAddr,
			pktMd.DstAddr, pktMd.Protocol, pktMd.SrcPort, pktMd.DstPort)
		if err != nil {
			log.WithFields(log.Fields{
				"srcAddr":  pktMd.SrcAddr.String(),
				"dstAddr":  pktMd.DstAddr.String(),
				"protocol": pktMd.Protocol,
				"srcPort":  pktMd.SrcPort,
				"dstPort":  pktMd.DstPort,
				"error":    err.Error(),
			}).Error("failed to construct INT payload for 5-tuple")
		}
		pktMd.DataPlaneReport.Payload = payload
	}

	payload := gopacket.Payload(pktMd.DataPlaneReport.LayerPayload())
	if pktMd.EncapMode == "vxlan" {
		// strip VXLAN out - our design choice is to report only the inner headers
		payload = payload[SizeEthernetIPv4UDPVXLAN:]
	}

	if !pktMd.MatchedPostNAT && !pktMd.DataPlaneReport.PreNATDestinationIP.IsUnspecified() &&
		pktMd.DataPlaneReport.PreNATDestinationPort != 0 &&
		!pktMd.DataPlaneReport.PreNATSourceIP.IsUnspecified() &&
		pktMd.DataPlaneReport.PreNATSourcePort != 0 {
		// if a watchlist matched on pre-NAT and data plane provides pre-NAT IP and port we should restore an original IP and port
		// FIXME: this should be changed once INT collector will have support for NAT correlation
		copy(payload[OffsetDestinationIPNoEncap-4:OffsetDestinationIPNoEncap], pktMd.DataPlaneReport.PreNATSourceIP)
		copy(payload[OffsetDestinationIPNoEncap:OffsetDestinationIPNoEncap+4], pktMd.DataPlaneReport.PreNATDestinationIP)
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, pktMd.DataPlaneReport.PreNATDestinationPort)
		copy(payload[OffsetDestinationPortNoEncap:OffsetDestinationPortNoEncap+2], b)
		binary.BigEndian.PutUint16(b, pktMd.DataPlaneReport.PreNATSourcePort)
		copy(payload[OffsetDestinationPortNoEncap-2:OffsetDestinationPortNoEncap], b)
	}

	return payload
}

func stringify5TupleFromPayload(payload gopacket.Payload) string {
	var srcAddr, dstAddr net.IP
	var srcPort, dstPort uint16
	var protocol uint8

	pkt := gopacket.NewPacket(payload, layers.LayerTypeEthernet, gopacket.Default)

	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		srcAddr = ipv4.SrcIP
		dstAddr = ipv4.DstIP
		protocol = uint8(ipv4.Protocol)

		if l4Layer := pkt.Layer(ipv4.NextLayerType()); l4Layer != nil {
			switch ipv4.Protocol {
			case layers.IPProtocolTCP:
				tcp, _ := l4Layer.(*layers.TCP)
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
			case layers.IPProtocolUDP:
				udp, _ := l4Layer.(*layers.UDP)
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			}
		}
	} else {
		return "failed to build 5-tuple from payload, no IPv4 layer?"
	}

	return fmt.Sprintf("SrcIP=%v, DstIP=%v, Protocol=%v, SrcPort=%v, DstPort=%v",
		srcAddr.String(), dstAddr.String(), protocol, srcPort, dstPort)
}

func buildINTFlowReport(pktMd *dataplane.PacketMetadata, switchID uint32, hwID uint8, seqNo uint32) ([]byte, error) {
	fixedReport := getINTFixedHeader(pktMd, hwID, seqNo)
	fixedReport.NProto = NProtoTelemetrySwitchLocal
	fixedReport.TrackedFlowAssociation = true
	commonHeader := getINTCommonHeader(pktMd, switchID)
	localReport := INTLocalReportHeader{
		INTCommonReportHeader: commonHeader,
		QueueOccupancy:        0,
		EgressTimestamp:       uint32(pktMd.DataPlaneReport.EgressTimestamp),
	}
	payload := getINTPayload(pktMd)

	log.WithFields(log.Fields{
		"fixed-report": fixedReport,
		"flow-report":  localReport,
		"5-tuple":      stringify5TupleFromPayload(payload),
	}).Debug("INT Flow Report built")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts,
		&fixedReport,
		&localReport,
		payload)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to serialize INT Flow Report: %v", err)
	}

	return buf.Bytes(), nil
}

func buildINTDropReport(pktMd *dataplane.PacketMetadata, switchID uint32, hwID uint8, seqNo uint32) ([]byte, error) {
	fixedReport := getINTFixedHeader(pktMd, hwID, seqNo)
	fixedReport.Dropped = true
	fixedReport.NProto = NProtoTelemetryDrop
	commonHeader := getINTCommonHeader(pktMd, switchID)
	payload := getINTPayload(pktMd)

	dropReport := INTDropReportHeader{
		INTCommonReportHeader: commonHeader,
		DropReason:            dropReasonConvertFromDatapathToINT(pktMd.DataPlaneReport.Reason),
	}

	log.WithFields(log.Fields{
		"fixed-report": fixedReport,
		"drop-report":  dropReport,
		"5-tuple":      stringify5TupleFromPayload(payload),
	}).Debug("INT Drop Report built")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts,
		&fixedReport,
		&dropReport,
		payload)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to serialize INT Flow Report: %v", err)
	}

	return buf.Bytes(), nil
}

func BuildINTReport(pktMd *dataplane.PacketMetadata, switchID uint32, hwID uint8, seqNo uint32) (data []byte, err error) {
	switch pktMd.DataPlaneReport.Type {
	case dataplane.TraceReport:
		data, err = buildINTFlowReport(pktMd, switchID, hwID, seqNo)
	case dataplane.DropReport:
		data, err = buildINTDropReport(pktMd, switchID, hwID, seqNo)
	default:
		return []byte{}, fmt.Errorf("unknown report type")
	}

	return data, err
}