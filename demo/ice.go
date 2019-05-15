package demo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
	"unicode/utf8"
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
type StunAttr []byte

func NewStunPacket(typ uint16, tid []byte) StunPacket {
	p := StunPacket(make([]byte, stunHeaderSize, stunHeaderSize))
	p.SetType(typ)
	p.SetLength(0)
	p.setCookie(stunMagicCookie)
	p.SetTransactionId(tid)
	return p
}

func NewStunPacketWithRandomTid(typ uint16) StunPacket {
	p := NewStunPacket(typ, nil)
	// TODO: Seed rand.
	rand.Reader.Read(p.TransactionId())
	return p
}

func VerifyStunPacket(b []byte) StunPacket {
	if len(b) < stunHeaderSize {
		return nil
	}
	p := StunPacket(b)
	if p.cookie() != 0x2112A442 {
		return nil
	}
	return p
}

func (p StunPacket) typeBytes() []byte {
	return p[0:2]
}

func (p StunPacket) Type() uint16 {
	return binary.BigEndian.Uint16(p.typeBytes())
}

func (p StunPacket) SetType(typ uint16) {
	binary.BigEndian.PutUint16(p.typeBytes(), typ)
}

func (p StunPacket) lengthBytes() []byte {
	return p[2:4]
}

func (p StunPacket) Length() uint16 {
	return binary.BigEndian.Uint16(p.lengthBytes())
}

func (p StunPacket) SetLength(length uint16) {
	binary.BigEndian.PutUint16(p.lengthBytes(), length)
}

func (p StunPacket) cookieBytes() []byte {
	return p[4:8]
}

func (p StunPacket) cookie() uint32 {
	return binary.BigEndian.Uint32(p.cookieBytes())
}

func (p StunPacket) setCookie(cookie uint32) {
	binary.BigEndian.PutUint32(p.cookieBytes(), cookie)
}

func (p StunPacket) TransactionId() []byte {
	return p[8:20]
}

func (p StunPacket) SetTransactionId(tid []byte) {
	copy(p.TransactionId(), tid)
}

func (p StunPacket) attrsBytes() []byte {
	if len(p) < int(stunHeaderSize+p.Length()) {
		return nil
	}
	return p[stunHeaderSize:][:p.Length()]
}

// Returns nil if it fails
func verifyStunAttr(b []byte) StunAttr {
	if len(b) < stunAttrHeaderSize {
		return nil
	}
	a := StunAttr(b)
	if len(b) < stunAttrHeaderSize+int(a.length()) {
		return nil
	}
	return a
}

func (a StunAttr) typeBytes() []byte {
	return a[0:2]
}

func (a StunAttr) Type() uint16 {
	return binary.BigEndian.Uint16(a.typeBytes())
}

func (a StunAttr) SetType(typ uint16) {
	binary.BigEndian.PutUint16(a.typeBytes(), typ)
}

func (a StunAttr) lengthBytes() []byte {
	return a[2:4]
}

func (a StunAttr) length() uint16 {
	return binary.BigEndian.Uint16(a.lengthBytes())
}

func (a StunAttr) setLength(length uint16) {
	binary.BigEndian.PutUint16(a.lengthBytes(), length)
}

func (a StunAttr) Bytes() []byte {
	return a[stunAttrHeaderSize:][:a.length()]
}

func (p StunPacket) AddUsername(username string) StunPacket {
	usernameB := []byte(username)
	p, a := p.addAttr(stunAttrUsername, uint16(len(usernameB)))
	copy(a.Bytes(), usernameB)
	return p
}

func (p StunPacket) FindUsername() (string, bool) {
	a, _ := p.findAttr(stunAttrUsername)
	if a == nil || !utf8.Valid(a.Bytes()) {
		return "", false
	}
	return string(a.Bytes()), true
}

func (p StunPacket) AddMessageIntegrity(key []byte) StunPacket {
	truncatedLength := len(p)
	p, a := p.addAttr(stunAttrMessageIntegrity, sha1.Size)
	copy(a.Bytes(), p.computeMessageIntegrity(key, truncatedLength))
	return p
}

func (p StunPacket) ValidateMessageIntegrity(key []byte) bool {
	a, truncatedLength := p.findAttr(stunAttrMessageIntegrity)
	if a == nil {
		return false
	}
	return hmac.Equal(a.Bytes(), p.computeMessageIntegrity(key, truncatedLength))
}

func (p StunPacket) computeMessageIntegrity(key []byte, truncatedLength int) []byte {
	// Tricky part: Include a funny length
	oldLength := p.Length()
	p.SetLength(uint16(truncatedLength + stunAttrHeaderSize))
	defer p.SetLength(oldLength)

	h := hmac.New(sha1.New, key)
	h.Write(p[:truncatedLength])
	return h.Sum(nil)
}

func (p StunPacket) AddFingerprint() StunPacket {
	truncatedLength := len(p)
	p, a := p.addAttr(stunAttrFingerprint, 4)
	binary.BigEndian.PutUint32(a.Bytes(), p.computeFingerprint(truncatedLength))
	return p
}

func (p StunPacket) ValidateFingerprint() bool {
	a, truncatedLength := p.findAttr(stunAttrFingerprint)
	if a == nil {
		return false
	}
	return p.computeFingerprint(truncatedLength) == binary.BigEndian.Uint32(a.Bytes())
}

func (p StunPacket) computeFingerprint(truncatedLength int) uint32 {
	return crc32.ChecksumIEEE(p[:truncatedLength]) ^ 0x5354554E
}

// Offset relative to the start of the packet
func (p StunPacket) findAttr(typ uint16) (StunAttr, int) {
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

func (p StunPacket) addAttr(typ uint16, length uint16) (StunPacket, StunAttr) {
	p2len := p.Length() + stunAttrHeaderSize + roundUpTo4ByteBoundary(length)
	p1size := stunHeaderSize + p.Length()
	p2size := stunHeaderSize + p2len
	p2 := StunPacket(make([]byte, p2size))
	copy(p2, p[:p1size])
	p2.SetLength(p2len)

	a := StunAttr(p2[p1size:])
	a.SetType(typ)
	a.setLength(length)
	return p2, a
}

func roundUpTo4ByteBoundary(val uint16) uint16 {
	rem := val % 4
	if rem > 0 {
		return val + 4 - rem
	}
	return val
}
