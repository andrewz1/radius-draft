package radius

import (
	"errors"
	"strings"
)

func attrKey(atype AttrType, vid VendorID, vtype VendorType) uint64 {
	if atype != AttrVSA {
		return uint64(atype)
	}
	return (uint64(vid) << 16) | (uint64(vtype) << 8) | uint64(atype)
}

func nameKey(name string) string {
	return strings.ToLower(name)
}

// Put attrs in dictionary

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

func MustAddAttrFull(name string, atype AttrType, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc, tagged bool) {
	err := AddAttrFull(name, atype, vid, vtype, dtype, enc, tagged)
	if err != nil {
		panic(err)
	}
}

func AddAttr(name string, atype AttrType, dtype AttrDType) error {
	return AddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, false)
}

func MustAddAttr(name string, atype AttrType, dtype AttrDType) {
	MustAddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, false)
}

func AddAttrEnc(name string, atype AttrType, dtype AttrDType, enc AttrEnc) error {
	return AddAttrFull(name, atype, 0, 0, dtype, enc, false)
}

func MustAddAttrEnc(name string, atype AttrType, dtype AttrDType, enc AttrEnc) {
	MustAddAttrFull(name, atype, 0, 0, dtype, enc, false)
}

func AddAttrTag(name string, atype AttrType, dtype AttrDType) error {
	return AddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, true)
}

func MustAddAttrTag(name string, atype AttrType, dtype AttrDType) {
	MustAddAttrFull(name, atype, 0, 0, dtype, AttrEncNone, true)
}

func AddAttrEncTag(name string, atype AttrType, dtype AttrDType, enc AttrEnc) error {
	return AddAttrFull(name, atype, 0, 0, dtype, enc, true)
}

func MustAddAttrEncTag(name string, atype AttrType, dtype AttrDType, enc AttrEnc) {
	MustAddAttrFull(name, atype, 0, 0, dtype, enc, true)
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

func AddVSATag(name string, vid VendorID, vtype VendorType, dtype AttrDType) error {
	return AddAttrFull(name, AttrVSA, vid, vtype, dtype, AttrEncNone, true)
}

func MustAddVSATag(name string, vid VendorID, vtype VendorType, dtype AttrDType) {
	MustAddAttrFull(name, AttrVSA, vid, vtype, dtype, AttrEncNone, true)
}

func AddVSAEncTag(name string, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc) error {
	return AddAttrFull(name, AttrVSA, vid, vtype, dtype, enc, true)
}

func MustAddVSAEncTag(name string, vid VendorID, vtype VendorType, dtype AttrDType, enc AttrEnc) {
	MustAddAttrFull(name, AttrVSA, vid, vtype, dtype, enc, true)
}

// Get attrs from dictionary

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
