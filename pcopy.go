package radius

import "encoding/binary"

func roundup64(x int) int {
	if rm := x & int(63); rm != 0 {
		x = x + 64 - rm
	}
	return x
}

func PacketDup(src []byte) (dst []byte) {
	pl := int(binary.BigEndian.Uint16(src[2:]))
	if pl > len(src) {
		return nil
	}
	dst = make([]byte, 0, roundup64(pl))
	dst = append(dst, src[:pl]...)
	return
}
