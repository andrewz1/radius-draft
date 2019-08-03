package radius

import (
	"encoding/binary"
	"errors"
)

type RadiusCode byte

// RFC constants
const (
	AccessRequest      RadiusCode = 1
	AccessAccept       RadiusCode = 2
	AccessReject       RadiusCode = 3
	AccountingRequest  RadiusCode = 4
	AccountingResponse RadiusCode = 5
	AccountingStatus   RadiusCode = 6
	PasswordRequest    RadiusCode = 7
	PasswordAck        RadiusCode = 8
	PasswordReject     RadiusCode = 9
	AccountingMessage  RadiusCode = 10
	AccessChallenge    RadiusCode = 11
	StatusServer       RadiusCode = 12
	StatusClient       RadiusCode = 13
	DisconnectRequest  RadiusCode = 40
	DisconnectACK      RadiusCode = 41
	DisconnectNAK      RadiusCode = 42
	CoARequest         RadiusCode = 43
	CoAACK             RadiusCode = 44
	CoANAK             RadiusCode = 45
)

const (
	MinPLen = 20   // Min packet len
	MaxPLen = 4096 // Max packet len
)

type Packet struct {
	code   RadiusCode  // Radius packet code
	id     byte        // Packet ID
	len    uint16      // Packet len
	auth   []byte      // Auth data
	attrs  []*Attr     // Attr slice
	vids   []VendorID  // Vendor IDs form packet
	secret []byte      // Radius shared secret
	data   []byte      // Raw packet data
	udata  interface{} // User data
}

func ParsePacket(buf []byte) (pkt *Packet, err error) {
	var (
		pl   int                   // packet len
		rb   *rBuf                 // read buffer
		at   byte                  // attr type
		ad   []byte                // attr data
		vid  VendorID              // vendor id
		vmap map[VendorID]struct{} // map for VSA
	)

	if len(buf) < MinPLen {
		err = errors.New("Packet too short")
		return
	}
	pl = int(binary.BigEndian.Uint16(buf[2:]))
	if pl < MinPLen || pl > MaxPLen || pl > len(buf) {
		err = errors.New("Packet len error")
		return
	}
	pkt = &Packet{
		code: RadiusCode(buf[0]),
		id:   buf[1],
		len:  uint16(pl),
		auth: buf[4:20],
		data: buf,
	}
	if pl == MinPLen {
		return
	}
	rb = newBuf(buf[MinPLen:])
	defer func() {
		if err != nil && pkt != nil {
			for _, a := range pkt.attrs {
				a.pkt = nil // remove any ref to packet data
			}
			pkt = nil
		}
	}()
	vmap = make(map[VendorID]struct{})
	for rb.getLeft() >= 2 {
		if at, ad, err = rb.getAttr(); err != nil {
			return
		}
		if AttrType(at) != AttrVSA { // plain attr
			pkt.parseAttr(AttrType(at), ad)
		} else { // VSA
			if vid, err = pkt.parseVSA(ad); err != nil {
				return
			}
			vmap[vid] = struct{}{}
		}
	}
	pkt.vids = make([]VendorID, 0, len(vmap))
	for v := range vmap {
		pkt.vids = append(pkt.vids, v)
	}
	return
}

func (p *Packet) parseAttr(at AttrType, ad []byte) {
	var attr *Attr // attribute

	attr = &Attr{
		atype: at,
		alen:  byte(len(ad) + 2),
		ad:    GetAttrByAttr(at),
		pkt:   p,
	}
	if attr.ad != nil && attr.ad.IsTagged() {
		attr.tag = ad[0]
		attr.data = ad[1:]
	} else {
		attr.data = ad
	}
	p.attrs = append(p.attrs, attr)
}

func (p *Packet) parseVSA(adata []byte) (vid VendorID, err error) {
	var (
		rb   *rBuf  // nested read buffer
		vt   byte   // vendor type
		vd   []byte // vendor data
		attr *Attr  // attribute
	)

	if len(adata) < 6 {
		err = errors.New("VSA too short")
		return
	}
	vid = VendorID(binary.BigEndian.Uint32(adata))
	rb = newBuf(adata[4:])
	for rb.getLeft() >= 2 {
		if vt, vd, err = rb.getAttr(); err != nil {
			return
		}
		attr = &Attr{
			atype: AttrVSA,
			alen:  byte(len(vd) + 8), // TODO: detect packed VSAs
			vid:   vid,
			vtype: VendorType(vt),
			vlen:  byte(len(vd) + 2),
			ad:    GetVSAByAttr(vid, VendorType(vt)),
			pkt:   p,
		}
		if attr.ad != nil && attr.ad.IsTagged() {
			attr.tag = vd[0]
			attr.data = vd[1:]
		} else {
			attr.data = vd
		}
		p.attrs = append(p.attrs, attr)
	}
	return
}

func (p *Packet) GetUserData() interface{} {
	if p == nil {
		return nil
	}
	return p.udata
}

func (p *Packet) SetUserData(udata interface{}) {
	if p == nil {
		return
	}
	p.udata = udata
}

func (p *Packet) GetSecret() []byte {
	if p == nil {
		return nil
	}
	return p.secret
}

func (p *Packet) SetSecret(secret []byte) {
	if p == nil {
		return
	}
	p.secret = secret
}
