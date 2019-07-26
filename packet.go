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
		at   AttrType              // attr type
		vid  VendorID              // vendor id
		vmap map[VendorID]struct{} // map for VSA
	)

	if len(buf) < MinPLen {
		err = errors.New("Packet too short")
		return
	}
	if pl = int(binary.BigEndian.Uint16(buf[2:])); pl < len(buf) {
		err = errors.New("Packet len error")
		return
	}
	rb = newBuf(buf[:pl])
	defer func() {
		var ok bool
		if r := recover(); r != nil {
			if err, ok = r.(error); !ok {
				err = errors.New("Panic in ParsePacket")
			}
		}
		if err != nil && pkt != nil {
			for _, a := range pkt.attrs {
				a.pkt = nil // remove any ref to packet data
			}
			pkt = nil
		}
	}()
	pkt = &Packet{
		code: RadiusCode(rb.getByte()),
		id:   rb.getByte(),
		len:  rb.getUInt16(),
		auth: rb.getBytes(16),
		data: rb.getBuf(),
	}
	vmap = make(map[VendorID]struct{})
	for rb.getLeft() >= 2 {
		if at = AttrType(rb.getByte()); at != AttrVSA { // plain attr
			if err = pkt.parseAttr(at, rb); err != nil {
				return
			}
		} else { // VSA
			if vid, err = pkt.parseVSA(rb); err != nil {
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

func (p *Packet) parseAttr(at AttrType, rb *rBuf) (err error) {
	var (
		al    byte      // attr len
		alInt int       // calculated attr len
		ad    *AttrData // attr data
		tg    byte      // attr tag
	)

	defer func() {
		var ok bool
		if r := recover(); r != nil {
			if err, ok = r.(error); !ok {
				err = errors.New("Panic in parseAttr")
			}
		}
	}()
	al = rb.getByte()
	if alInt = int(al) - 2; alInt < 0 {
		err = errors.New("Attr len error")
		return
	}
	ad = GetAttrByAttr(at)
	tg = 0
	if ad.IsTagged() {
		tg = rb.getByte()
		if alInt--; alInt < 0 {
			err = errors.New("Attr len error")
			return
		}
	}
	p.attrs = append(p.attrs, &Attr{
		atype: at,
		alen:  al,
		tag:   tg,
		data:  rb.getBytes(alInt),
		ad:    ad,
		pkt:   p,
	})
	return
}

func (p *Packet) parseVSA(rb *rBuf) (vid VendorID, err error) {
	var (
		al    byte       // attr len
		alInt int        // calculated attr len
		nrb   *rBuf      // nested read buffer
		vt    VendorType // vendor type
		vl    byte       // vendor len
		vlInt int        // calculated vendor len
		ad    *AttrData  // attr data
		tg    byte       // attr tag
	)

	defer func() {
		var ok bool
		if r := recover(); r != nil {
			if err, ok = r.(error); !ok {
				err = errors.New("Panic in parseVSA")
			}
		}
		if err != nil {
			vid = 0
		}
	}()
	al = rb.getByte()
	if alInt = int(al) - 6; alInt < 0 {
		err = errors.New("Attr len error")
		return
	}
	vid = VendorID(rb.getUInt32())
	nrb = rb.nestedBuf(alInt)
	for nrb.getLeft() >= 2 {
		vt = VendorType(nrb.getByte())
		vl = nrb.getByte()
		if vlInt = int(vl) - 2; vlInt < 0 {
			err = errors.New("Attr len error")
			return
		}
		ad = GetVSAByAttr(vid, vt)
		tg = 0
		if ad.IsTagged() {
			tg = nrb.getByte()
			if vlInt--; vlInt < 0 {
				err = errors.New("Attr len error")
				return
			}
		}
		p.attrs = append(p.attrs, &Attr{
			atype: AttrVSA,
			alen:  vl + 6, // TODO: detect packed VSAs
			vid:   vid,
			vtype: vt,
			vlen:  vl,
			tag:   tg,
			data:  nrb.getBytes(vlInt),
			ad:    ad,
			pkt:   p,
		})
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
