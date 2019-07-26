package radius

import (
	"encoding/binary"
	"errors"
)

var (
	errNoData = errors.New("No data in buffer")
	// errInvalid = errors.New("Invalid parameter")
)

type rBuf struct {
	buf []byte // buffer data
	bp  int    // buffer pointer
	bl  int    // data left in buffer
}

func newBuf(buf []byte) *rBuf { // TODO
	return &rBuf{
		buf: append([]byte(nil), buf...),
		bl:  len(buf),
	}
}

// func acquireBuf(buf []byte) *rBuf { // TODO
// 	return &rBuf{
// 		buf: buf,
// 		bl:  len(buf),
// 	}
// }

// func releaseBuf(rb *rBuf) {
// 	// TODO
// }

func (rb *rBuf) getLeft() int {
	return rb.bl
}

func (rb *rBuf) getBuf() []byte {
	return rb.buf
}

func (rb *rBuf) nestedBuf(n int) *rBuf {
	return &rBuf{
		buf: rb.getBytes(n),
		bl:  n,
	}
}

func (rb *rBuf) getByte() byte {
	if rb.bl < 1 {
		panic(errNoData)
	}
	defer func() {
		rb.bp++
		rb.bl--
	}()
	return rb.buf[rb.bp]
}

func (rb *rBuf) getUInt16() uint16 {
	if rb.bl < 2 {
		panic(errNoData)
	}
	defer func() {
		rb.bp += 2
		rb.bl -= 2
	}()
	return binary.BigEndian.Uint16(rb.buf[rb.bp:])
}

func (rb *rBuf) getUInt32() uint32 {
	if rb.bl < 4 {
		panic(errNoData)
	}
	defer func() {
		rb.bp += 4
		rb.bl -= 4
	}()
	return binary.BigEndian.Uint32(rb.buf[rb.bp:])
}

func (rb *rBuf) getBytes(n int) []byte {
	if rb.bl < n {
		panic(errNoData)
	}
	defer func() {
		rb.bp += n
		rb.bl -= n
	}()
	return rb.buf[rb.bp : rb.bp+n]
}
