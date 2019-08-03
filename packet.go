package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var errInvalidFormat = errors.New("Invalid data format")

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
	reply  bool        // Is this reply
}

func (rc RadiusCode) String() string {
	switch rc {
	case AccessRequest:
		return "AccessRequest"
	case AccessAccept:
		return "AccessAccept"
	case AccessReject:
		return "AccessReject"
	case AccountingRequest:
		return "AccountingRequest"
	case AccountingResponse:
		return "AccountingResponse"
	case AccountingStatus:
		return "AccountingStatus"
	case PasswordRequest:
		return "PasswordRequest"
	case PasswordAck:
		return "PasswordAck"
	case PasswordReject:
		return "PasswordReject"
	case AccountingMessage:
		return "AccountingMessage"
	case AccessChallenge:
		return "AccessChallenge"
	case StatusServer:
		return "StatusServer"
	case StatusClient:
		return "StatusClient"
	case DisconnectRequest:
		return "DisconnectRequest"
	case DisconnectACK:
		return "DisconnectACK"
	case DisconnectNAK:
		return "DisconnectNAK"
	case CoARequest:
		return "CoARequest"
	case CoAACK:
		return "CoAACK"
	case CoANAK:
		return "CoANAK"
	default:
		return fmt.Sprintf("Unknown(%d)", rc)
	}
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

func (p *Packet) GetCode() RadiusCode {
	if p == nil {
		return RadiusCode(0)
	}
	return p.code
}

func (p *Packet) SetCode(code RadiusCode) {
	if p == nil {
		return
	}
	p.code = code
}

func (p *Packet) GetVIDs() []VendorID {
	if p == nil {
		return nil
	}
	return p.vids
}

func (p *Packet) AddAttrSimple(attr *Attr) {
	if p == nil {
		return
	}
	attr.pkt = p
	p.attrs = append(p.attrs, attr)
}

func attrConv(ad AttrDType, v interface{}) ([]byte, error) {
	switch ad {
	case DTypeRaw:
		av, ok := v.([]byte)
		if !ok {
			return nil, errInvalidFormat
		}
		return av, nil
	case DTypeString:
		av, ok := v.(string)
		if !ok {
			return nil, errInvalidFormat
		}
		return []byte(av), nil
	case DTypeIP4:
		av, ok := v.(net.IP)
		if !ok {
			return nil, errInvalidFormat
		}
		if av = av.To4(); av == nil {
			return nil, errInvalidFormat
		}
		return av, nil
	case DTypeInt:
		av, ok := v.(uint32)
		if !ok {
			return nil, errInvalidFormat
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, av)
		return b, nil
	case DTypeInt64:
		av, ok := v.(uint64)
		if !ok {
			return nil, errInvalidFormat
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, av)
		return b, nil
	case DTypeDate:
		switch v.(type) {
		case time.Time:
			av := v.(time.Time)
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(av.Unix()))
			return b, nil
		case int64:
			av := v.(int64)
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(av))
			return b, nil
		default:
			return nil, errInvalidFormat
		}
	case DTypeIfID:
		av, ok := v.(uint64)
		if !ok {
			return nil, errInvalidFormat
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, av)
		return b, nil
	case DTypeIP6:
		av, ok := v.(net.IP)
		if !ok {
			return nil, errInvalidFormat
		}
		if av = av.To16(); av == nil {
			return nil, errInvalidFormat
		}
		return av, nil
	case DTypeByte:
		av, ok := v.(byte)
		if !ok {
			return nil, errInvalidFormat
		}
		return []byte{av}, nil
	case DTypeEth:
		av, ok := v.(net.HardwareAddr)
		if !ok || len(av) != 6 {
			return nil, errInvalidFormat
		}
		return av, nil
	case DTypeShort:
		av, ok := v.(uint16)
		if !ok {
			return nil, errInvalidFormat
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, av)
		return b, nil
	}
	return nil, errInvalidFormat
}

func (p *Packet) AddAttr(atype AttrType, vid VendorID, vtype VendorType, tag byte, data interface{}) error {
	var err error

	if p == nil {
		return errors.New("Packet empty")
	}
	attr := &Attr{
		atype: atype,
		ad:    GetAttrByAttrFull(atype, vid, vtype),
	}
	if attr.IsVSA() {
		attr.vid = vid
		attr.vtype = vtype
	}
	if attr.ad == nil {
		// for unknown attrs only raw data can be set
		av, ok := data.([]byte)
		if !ok {
			return errInvalidFormat
		}
		attr.data = av
	} else {
		if attr.data, err = attrConv(attr.ad.dtype, data); err != nil {
			return err
		}
		if attr.ad.IsTagged() {
			attr.tag = tag
		}
	}
	if attr.IsVSA() {
		attr.alen = byte(len(attr.data) + 8)
		attr.vlen = byte(len(attr.data) + 2)
	} else {
		attr.alen = byte(len(attr.data) + 2)
	}
	attr.pkt = p
	p.attrs = append(p.attrs, attr)
	return nil
}

func (p *Packet) String() (r string) {
	if p == nil {
		return
	}
	r += fmt.Sprintf("Code: %s, ID: %d, Len: %d, Auth: %02x\n", p.code, p.id, p.len, p.auth)
	for _, attr := range p.attrs {
		if attr.ad != nil {
			r += fmt.Sprintf("  %s: ", attr.ad.name)
		} else {
			if attr.atype == AttrVSA {
				r += fmt.Sprintf("  VSA-%d-%d: ", attr.vid, attr.vtype)
			} else {
				r += fmt.Sprintf("  Attr-%d: ", attr.atype)
			}
		}
		if attr.ad.IsTagged() {
			r += fmt.Sprintf("[%d] ", attr.tag)
		}
		ed := attr.GetEData()
		switch ed.(type) {
		case []byte:
			r += fmt.Sprintf("%02x", ed.([]byte))
		default:
			r += fmt.Sprintf("%v", ed)
		}
		r += fmt.Sprint("\n")
	}
	return
}

func (p *Packet) Reply() *Packet {
	if p == nil {
		return nil
	}
	return &Packet{
		id:     p.id,
		auth:   p.auth,
		vids:   p.vids,
		secret: p.secret,
		udata:  p.udata,
		reply:  true,
	}
}

func (p *Packet) BufCalc() (sum int) {
	if p == nil {
		return
	}
	sum = MinPLen
	for _, a := range p.attrs {
		sum += int(a.alen)
	}
	return roundup64(sum)
}

func (p *Packet) Serialize() []byte {
	return nil
}
