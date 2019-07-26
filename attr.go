package radius

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
