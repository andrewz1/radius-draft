package radius

import (
	"sync"
)

// basic RADIUS Attr structs

// Attr encryption
type AttrEnc int

const (
	AttrEncNone AttrEnc = iota // No encryption
	AttrEncUsr                 // User-Password encryption
	AttrEncTun                 // Tunnel-Password encryption
	AttrEncAsc                 // Ascend’s proprietary encryption

)

// Attr data type
type AttrDType int

const (
	DTypeRaw    AttrDType = iota // byte slice
	DTypeString                  // string
	DTypeIP4                     // ip addr
	DTypeIP4Pfx                  // 6 bytes
	DTypeInt                     // uint32
	DTypeInt64                   // uint64
	DTypeDate                    // unix time 32 bit
	DTypeIfID                    // 8 bytes
	DTypeIP6                     // 16 bytes
	DTypeIP6Pfx                  // 18 bytes
	DTypeByte                    // one byte
	DTypeEth                     // 6 bytes, MAC
	DTypeShort                   // uint16
	DTypeSInt                    // signed int
	DTypeVSA                     // VSA
)

type AttrType byte   // Attr type
type VendorID uint32 // Vendor ID for VSA
type VendorType byte // Vendor type for VSA

const AttrVSA AttrType = 26

type AttrData struct {
	name   string
	atype  AttrType
	vid    VendorID
	vtype  VendorType
	dtype  AttrDType
	enc    AttrEnc
	tagged bool
}

type attrStore struct {
	sync.RWMutex // just in case RW
	byName       map[string]*AttrData
	byAttr       map[uint64]*AttrData
}

var attrDict = &attrStore{
	byName: make(map[string]*AttrData),
	byAttr: make(map[uint64]*AttrData),
}

func (ad *AttrData) IsTagged() bool {
	if ad == nil {
		return false // default is untagged
	}
	return ad.tagged
}

func (ad *AttrData) GetEnc() AttrEnc {
	if ad == nil {
		return AttrEncNone
	}
	return ad.enc
}

func (ad *AttrData) GetName() string {
	if ad == nil {
		return ""
	}
	return ad.name
}

func (ad *AttrData) GetDataType() AttrDType {
	if ad == nil {
		return DTypeRaw
	}
	return ad.dtype
}
