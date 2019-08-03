package radius

import (
	"encoding/binary"
	"net"
	"time"
)

type Attr struct {
	atype AttrType    // Attr type
	alen  byte        // Attr len
	vid   VendorID    // Vendor ID
	vtype VendorType  // Vendor Type
	vlen  byte        // Vendor len
	tag   byte        // Tag for tagged attrs
	data  []byte      // Raw attr data without tag
	edata interface{} // Evaluated data
	ad    *AttrData   // Attribute data from dict
	pkt   *Packet     // Packet which this attr is belongs
}

func (a *Attr) IsVSA() bool {
	return (a.atype == AttrVSA)
}

func (a *Attr) GetAttrType() AttrType {
	return a.atype
}

func (a *Attr) GetVSAType() (VendorID, VendorType) {
	return a.vid, a.vtype
}

func (a *Attr) GetTag() byte {
	return a.tag
}

func (a *Attr) GetAttrData() *AttrData {
	return a.ad
}

func (a *Attr) GetAttrPacket() *Packet {
	return a.pkt
}

func (a *Attr) GetData() []byte {
	return a.data
}

func (a *Attr) GetEData() interface{} {
	if a.edata != nil {
		return a.edata
	}
	if a.ad == nil {
		a.edata = a.data
		return a.edata
	}
	if a.ad.enc != AttrEncNone {
		a.edata = a.data
		return a.edata
	}
	switch a.ad.dtype {
	case DTypeString:
		a.edata = string(a.data)
	case DTypeIP4:
		if len(a.data) == 4 {
			a.edata = net.IP(a.data)
		}
	case DTypeInt:
		if len(a.data) == 4 {
			a.edata = binary.BigEndian.Uint32(a.data)
		}
	case DTypeInt64:
		if len(a.data) == 8 {
			a.edata = binary.BigEndian.Uint64(a.data)
		}
	case DTypeDate:
		if len(a.data) == 4 {
			t := binary.BigEndian.Uint32(a.data)
			a.edata = time.Unix(int64(t), 0)
		}
	case DTypeIfID:
		if len(a.data) == 8 {
			a.edata = binary.BigEndian.Uint64(a.data)
		}
	case DTypeIP6:
		if len(a.data) == 16 {
			a.edata = net.IP(a.data)
		}
	case DTypeByte:
		if len(a.data) == 1 {
			a.edata = a.data[0]
		}
	case DTypeEth:
		if len(a.data) == 6 {
			a.edata = net.HardwareAddr(a.data)
		}
	case DTypeShort:
		if len(a.data) == 2 {
			a.edata = binary.BigEndian.Uint16(a.data)
		}
	}
	if a.edata == nil {
		a.edata = a.data
	}
	return a.edata
}
