package demo

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
)

const (
	stunHeaderSize      = 20
	stunMagicCookie     = 0x2112A442
	StunBindingRequest  = 0x0001
	StunBindingResponse = 0x0101

	stunAttrHeaderSize       = 4
	stunAttrUsername         = 0x0006 // string
	stunAttrMessageIntegrity = 0x0008 // []byte
	stunAttrFingerprint      = 0x8028 // uint32
)

type StunPacket []byte

func (p StunPacket) typeBytes() []byte {
	return p[0:2]

}
func (p StunPacket) attrsLengthBytes() []byte {
	return p[2:4]
}

func (p StunPacket) cookieBytes() []byte {
	return p[4:8]
}

func (p StunPacket) TransactionId() []byte {
	return p[8:20]
}

func (p StunPacket) attrsBytes() []byte {
	return p[20:]
}

func (p StunPacket) Type() uint16 {
	return binary.BigEndian.Uint16(p.typeBytes())
}

func (p StunPacket) attrsLength() uint16 {
	return binary.BigEndian.Uint16(p.attrsLengthBytes())
}

func (p StunPacket) cookie() uint32 {
	return binary.BigEndian.Uint32(p.cookieBytes())
}

func (p StunPacket) totalClaimedLength() int {
	return stunHeaderSize + int(p.attrsLength())
}

func (p StunPacket) setType(typ uint16) {
	binary.BigEndian.PutUint16(p.typeBytes(), typ)
}

func (p StunPacket) setAttrsLength(length uint16) {
	binary.BigEndian.PutUint16(p.attrsLengthBytes(), length)
}

func (p StunPacket) setCookie(cookie uint32) {
	binary.BigEndian.PutUint32(p.cookieBytes(), cookie)
}

func (p StunPacket) setTransactionId(tid []byte) {
	copy(p.TransactionId(), tid)
}

func VerifyStunPacket(b []byte) StunPacket {
	if len(b) < stunHeaderSize {
		return nil
	}
	p := StunPacket(b)
	if p.cookie() != 0x2112A442 {
		return nil
	}
	if len(b) < p.totalClaimedLength() {
		return nil
	}
	// Chop off anything extra in the packet that's not needed.
	return StunPacket(b[:p.totalClaimedLength()])
}

func NewStunPacket(typ uint16, tid []byte) StunPacket {
	p := StunPacket(make([]byte, stunHeaderSize, stunHeaderSize))
	p.setType(typ)
	p.setAttrsLength(0)
	p.setCookie(stunMagicCookie)
	p.setTransactionId(tid)
	return p
}

type StunAttr []byte

func (a StunAttr) typeBytes() []byte {
	return a[0:2]
}

func (a StunAttr) lengthBytes() []byte {
	return a[2:4]
}

func (a StunAttr) bytes() []byte {
	return a[4:]
}

func (a StunAttr) Type() uint16 {
	return binary.BigEndian.Uint16(a.typeBytes())
}

func (a StunAttr) length() uint16 {
	return binary.BigEndian.Uint16(a.lengthBytes())
}

func (a StunAttr) totalClaimedLength() int {
	return stunAttrHeaderSize + int(a.length())
}

func (a StunAttr) setType(typ uint16) {
	binary.BigEndian.PutUint16(a.typeBytes(), typ)
}

func (a StunAttr) setLength(length uint16) {
	binary.BigEndian.PutUint16(a.lengthBytes(), length)
}

// Returns nil if it fails
func verifyStunAttr(b []byte) StunAttr {
	if len(b) < stunAttrHeaderSize {
		return nil
	}
	a := StunAttr(b)
	if len(b) < a.totalClaimedLength() {
		return nil
	}
	// Chop off anything we extra on the end of the buffer
	return StunAttr(b[:a.totalClaimedLength()])
}

// Offset relative to the start of the packet
func (p StunPacket) getAttr(typ uint16) (StunAttr, int) {
	b := p.attrsBytes()

	offset := 0
	for {
		a := verifyStunAttr(b[offset:])
		if a == nil || a.Type() == typ {
			return a, offset + stunHeaderSize
		}
		offset += (stunAttrHeaderSize + int(roundUpTo4ByteBoundary(a.length())))
	}
}

func (p1 StunPacket) appendAttr(attrType uint16, attrLength uint16) (StunPacket, StunAttr) {
	extraLength := int(stunAttrHeaderSize + roundUpTo4ByteBoundary(attrLength))
	p2 := StunPacket(make([]byte, len(p1)+extraLength))
	copy(p2, p1)
	p2.setAttrsLength(p1.attrsLength() + uint16(extraLength))
	a := StunAttr(p2[len(p1):])
	a.setType(attrType)
	a.setLength(attrLength)
	return p2, a
}

func roundUpTo4ByteBoundary(val uint16) uint16 {
	rem := val % 4
	if rem > 0 {
		return val + 4 - rem
	}
	return val
}

func (p StunPacket) AppendMessageIntegrity(key []byte) StunPacket {
	miOffset := p.totalClaimedLength()
	p, a := p.appendAttr(stunAttrMessageIntegrity, sha1.Size)
	copy(a.bytes(), p.computeMessageIntegrity(key, miOffset))
	return p
}

func (p StunPacket) ValidateMessageIntegrity(key []byte) bool {
	a, offset := p.getAttr(stunAttrMessageIntegrity)
	if a == nil {
		return false
	}
	return hmac.Equal(a.bytes(), p.computeMessageIntegrity(key, offset))
}

func (p StunPacket) computeMessageIntegrity(key []byte, miOffset int) []byte {
	// Tricky part: Include a funny length here temporarily
	oldAttrsLength := p.attrsLength()
	p.setAttrsLength(uint16(miOffset + stunAttrHeaderSize))
	defer p.setAttrsLength(oldAttrsLength)

	h := hmac.New(sha1.New, key)
	h.Write(p[:miOffset])
	return h.Sum(nil)
}

func (p StunPacket) AppendFingerprint() StunPacket {
	fpOffset := p.totalClaimedLength()
	p, a := p.appendAttr(stunAttrFingerprint, 4)
	binary.BigEndian.PutUint32(a.bytes(), p.computeFingerprint(fpOffset))
	return p
}

func (p StunPacket) ValidateFingerprint() bool {
	a, fpOffset := p.getAttr(stunAttrFingerprint)
	if a == nil {
		return false
	}
	return p.computeFingerprint(fpOffset) == binary.BigEndian.Uint32(a.bytes())
}

func (p StunPacket) computeFingerprint(fpOffset int) uint32 {
	return crc32.ChecksumIEEE(p[:fpOffset]) ^ 0x5354554E
}
