package inthostreporter

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	NProtoEthernet = 0
	NProtoTelemetryDrop = 1
	NProtoTelemetrySwitchLocal = 2

	SizeINTFixedHeader = 12
	SizeINTDropReportHeader = 12
	SizeINTFlowReportHeader = 16
)

var (
	LayerTypeINTReportFixedHeader = gopacket.RegisterLayerType(1001, gopacket.LayerTypeMetadata{
		Name:    "INTReportFixedHeader",
		// we won't be decoding INT Report Fixed Header as we only send reports.
		Decoder: gopacket.DecodeUnknown,
	})
	LayerTypeINTFlowReportHeader = gopacket.RegisterLayerType(1002, gopacket.LayerTypeMetadata{
		Name:    "INTFlowReport",
		// we won't be decoding INT Flow Report as we only send reports.
		Decoder: gopacket.DecodeUnknown,
	})
	LayerTypeINTDropReportHeader = gopacket.RegisterLayerType(1003, gopacket.LayerTypeMetadata{
		Name:    "INTDropReport",
		// we won't be decoding INT Drop Report as we only send reports.
		Decoder: gopacket.DecodeUnknown,
	})
)

type INTReportFixedHeader struct {
	layers.BaseLayer
	Version 			uint8
	NProto 				uint8
	// 1-bit field
	Dropped				bool
	// 1-bit field
	CongestedQueueAssociation bool
	// 1-bit field
	TrackedFlowAssociation bool
	// 6-bit field
	HwID				uint8
	SeqNo				uint32
	IngressTimestamp	uint32
}

type INTCommonReportHeader struct {
	layers.BaseLayer
	SwitchID			uint32
	IngressPort			uint16
	EgressPort			uint16
	QueueID				uint8
}

type INTDropReportHeader struct {
	layers.BaseLayer
	INTCommonReportHeader
	DropReason			uint8
}

type INTLocalReportHeader struct {
	layers.BaseLayer
	INTCommonReportHeader
	// 24-bit field
	QueueOccupancy		uint32
	EgressTimestamp		uint32
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

