package radius

import (
	"errors"
	"strings"
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

func attrKey(atype AttrType, vid VendorID, vtype VendorType) uint64 {
	if atype != AttrVSA {
		return uint64(atype)
	}
	return (uint64(vid) << 16) | (uint64(vtype) << 8) | uint64(atype)
}

func nameKey(name string) string {
	return strings.ToLower(name)
}

// AddAttrFull - full attribute add
func AddAttrFull(name string, atype AttrType, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc, tagged bool) (err error) {
	aKey := attrKey(atype, vid, vtype)
	nKey := nameKey(name)
	attrDict.Lock()
	defer attrDict.Unlock()
	_, okName := attrDict.byName[nKey]
	_, okAttr := attrDict.byAttr[aKey]
	if okName || okAttr {
		err = errors.New("Attribute exists: " + name)
		return
	}
	attr := &AttrData{
		name:   name,
		atype:  atype,
		vid:    vid,
		vtype:  vtype,
		dtype:  dtype,
		enc:    enc,
		tagged: tagged,
	}
	attrDict.byName[nKey] = attr
	attrDict.byAttr[aKey] = attr
	return
}

// MustAddAttrFull - full attribute add, panics on error
func MustAddAttrFull(name string, atype AttrType, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc, tagged bool) {
	err := AddAttrFull(name, atype, vid, vtype, dtype, enc, tagged)
	if err != nil {
		panic(err)
	}
}

// AddAttr - add plain attribute, enc = 0, tag = false
func AddAttr(name string, atype AttrType, dtype AttrDType) error {
	return AddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, false)
}

// MustAddAttr - add plain attribute, enc = 0, tag = false, panics on error
func MustAddAttr(name string, atype AttrType, dtype AttrDType) {
	MustAddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, false)
}

func AddAttrEnc(name string, atype AttrType, dtype AttrDType, enc AttrEnc) error {
	return AddAttrFull(name, atype, 0, 0, dtype, enc, false)
}

func MustAddAttrEnc(name string, atype AttrType, dtype AttrDType, enc AttrEnc) {
	MustAddAttrFull(name, atype, 0, 0, dtype, enc, false)
}

func AddAttrTag(name string, atype AttrType, dtype AttrDType, tagged bool) error {
	return AddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, tagged)
}

func MustAddAttrTag(name string, atype AttrType, dtype AttrDType, tagged bool) {
	MustAddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, tagged)
}

func AddAttrEncTag(name string, atype AttrType, dtype AttrDType, enc AttrEnc, tagged bool) error {
	return AddAttrFull(name, atype, 0, 0, dtype, enc, tagged)
}

func MustAddAttrEncTag(name string, atype AttrType, dtype AttrDType, enc AttrEnc, tagged bool) {
	MustAddAttrFull(name, atype, 0, 0, dtype, enc, tagged)
}

func AddVSA(name string, vid VendorID, vtype VendorType, dtype AttrDType) error {
	return AddAttrFull(name, AttrVSA, vid, vtype, dtype, AttrEncNone, false)
}

func MustAddVSA(name string, vid VendorID, vtype VendorType, dtype AttrDType) {
	MustAddAttrFull(name, AttrVSA, vid, vtype, dtype, AttrEncNone, false)
}

func AddVSAEnc(name string, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc) error {
	return AddAttrFull(name, AttrVSA, vid, vtype, dtype, enc, false)
}

func MustAddVSAEnc(name string, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc) {
	MustAddAttrFull(name, AttrVSA, vid, vtype, dtype, enc, false)
}

func AddVSATag(name string, vid VendorID, vtype VendorType, dtype AttrDType, tagged bool) error {
	return AddAttrFull(name, AttrVSA, vid, vtype, dtype, AttrEncNone, tagged)
}

func MustAddVSATag(name string, vid VendorID, vtype VendorType, dtype AttrDType, tagged bool) {
	MustAddAttrFull(name, AttrVSA, vid, vtype, dtype, AttrEncNone, tagged)
}

func AddVSAEncTag(name string, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc, tagged bool) error {
	return AddAttrFull(name, AttrVSA, vid, vtype, dtype, enc, tagged)
}

func MustAddVSAEncTag(name string, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc, tagged bool) {
	MustAddAttrFull(name, AttrVSA, vid, vtype, dtype, enc, tagged)
}

func GetAttrByName(name string) *AttrData {
	nKey := nameKey(name)
	attrDict.RLock()
	defer attrDict.RUnlock()
	if ad, ok := attrDict.byName[nKey]; ok {
		return ad
	}
	return nil
}

func MustGetAttrByName(name string) *AttrData {
	if ad := GetAttrByName(name); ad != nil {
		return ad
	}
	panic("Attribute not found: " + name)
}

func GetAttrByAttrFull(atype AttrType, vid VendorID, vtype VendorType) *AttrData {
	aKey := attrKey(atype, vid, vtype)
	attrDict.RLock()
	defer attrDict.RUnlock()
	if ad, ok := attrDict.byAttr[aKey]; ok {
		return ad
	}
	return nil
}

func MustGetAttrByAttrFull(atype AttrType, vid VendorID, vtype VendorType) *AttrData {
	if ad := GetAttrByAttrFull(atype, vid, vtype); ad != nil {
		return ad
	}
	panic("Attribute not found: byAttr") // TODO
}

func GetAttrByAttr(atype AttrType) *AttrData {
	return GetAttrByAttrFull(atype, 0, 0)
}

func MustGetAttrByAttr(atype AttrType) *AttrData {
	return MustGetAttrByAttrFull(atype, 0, 0)
}

func GetVSAByAttr(vid VendorID, vtype VendorType) *AttrData {
	return GetAttrByAttrFull(AttrVSA, vid, vtype)
}

func MustGetVSAByAttr(vid VendorID, vtype VendorType) *AttrData {
	return MustGetAttrByAttrFull(AttrVSA, vid, vtype)
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
