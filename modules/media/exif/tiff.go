package exif

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// TIFF parsing.
//
// The structure is small and completely regular: a header naming the byte order, an
// offset to the first directory, and directories of 12-byte entries. Everything
// awkward about EXIF is in what the values mean, not in how they are laid out, so this
// file deals only with structure and hands interpretation to module.go.

const (
	typeByte      = 1
	typeASCII     = 2
	typeShort     = 3
	typeLong      = 4
	typeRational  = 5
	typeUndefined = 7
	typeSRational = 10
)

// tiffHeader is a parsed TIFF block header.
type tiffHeader struct {
	byteOrder binary.ByteOrder
	// ifd0Offset is the absolute offset, within the TIFF block, of the first directory.
	ifd0Offset uint32
}

// parseTIFFHeader validates a TIFF block.
//
// The byte order has to be established before anything else can be read, and a file
// claiming little-endian with a big-endian marker in its offsets would otherwise be
// parsed into confident nonsense.
func parseTIFFHeader(b []byte) (*tiffHeader, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("exif: TIFF block is %d bytes, too short for a header", len(b))
	}
	var order binary.ByteOrder
	switch {
	case b[0] == 'I' && b[1] == 'I':
		order = binary.LittleEndian
	case b[0] == 'M' && b[1] == 'M':
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("exif: byte-order marker is %q%q, expected II or MM", b[0], b[1])
	}
	if order.Uint16(b[2:4]) != 42 {
		return nil, fmt.Errorf("exif: TIFF magic is %d, expected 42", order.Uint16(b[2:4]))
	}
	off := order.Uint32(b[4:8])
	if int64(off) < 8 || int64(off) >= int64(len(b)) {
		return nil, fmt.Errorf("exif: first directory offset %d is outside the %d byte block", off, len(b))
	}
	return &tiffHeader{byteOrder: order, ifd0Offset: off}, nil
}

// entry is one directory entry, with its value decoded where it is small enough to be
// inline.
type entry struct {
	tag   uint16
	typ   uint16
	count uint32
	// value is the decoded scalar for a single-value entry that fits inline, and the
	// decoded string for an ASCII entry.
	value any
	// bytes is the raw bytes of a value, resolved from the data area when it did not
	// fit inline.
	bytes []byte
	// offset is where the value lives in the block, for entries needing it.
	offset int
}

// ifd is a parsed image file directory.
type ifd struct {
	entries []entry
	// next is the offset of the following directory, or zero.
	next uint32
}

// tag returns an entry by tag.
func (d *ifd) tag(tag uint16) (entry, bool) {
	for _, e := range d.entries {
		if e.tag == tag {
			return e, true
		}
	}
	return entry{}, false
}

func (d *ifd) string(tag uint16) string {
	e, ok := d.tag(tag)
	if !ok {
		return ""
	}
	if s, ok := e.value.(string); ok {
		return s
	}
	return ""
}

func (d *ifd) strings(tag uint16) []string {
	e, ok := d.tag(tag)
	if !ok {
		return nil
	}
	if s, ok := e.value.(string); ok {
		// A multi-valued ASCII entry is NUL separated.
		var out []string
		for _, part := range strings.Split(s, "\x00") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

func (d *ifd) int(tag uint16) (int, bool) {
	e, ok := d.tag(tag)
	if !ok {
		return 0, false
	}
	switch v := e.value.(type) {
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case int64:
		return int(v), true
	case uint64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

// parseIFD reads one directory at an offset.
func parseIFD(block []byte, h *tiffHeader, offset uint32) (*ifd, error) {
	if int64(offset) < 0 || int64(offset)+2 > int64(len(block)) {
		return nil, fmt.Errorf("exif: directory offset %d is outside the block", offset)
	}
	count := h.byteOrder.Uint16(block[offset : offset+2])
	// Each entry is 12 bytes and the directory is followed by a 4-byte link. A count
	// that cannot fit is a corrupt or hostile file.
	if int64(count)*12+2+4 > int64(len(block))-int64(offset) {
		return nil, fmt.Errorf("exif: directory declares %d entries, which does not fit in %d bytes",
			count, len(block)-int(offset))
	}
	d := &ifd{}
	pos := int(offset) + 2
	for i := 0; i < int(count); i++ {
		raw := block[pos : pos+12]
		pos += 12
		e := entry{
			tag:   h.byteOrder.Uint16(raw[0:2]),
			typ:   h.byteOrder.Uint16(raw[2:4]),
			count: h.byteOrder.Uint32(raw[4:8]),
		}
		if err := resolveValue(block, h, &e, raw); err != nil {
			// A single unresolvable entry does not invalidate the directory. Dropping
			// the whole thing would lose every other field along with the bad one, and a
			// corrupt entry is more likely a quirk of one camera than a whole-file fault.
			continue
		}
		d.entries = append(d.entries, e)
	}
	if pos+4 <= len(block) {
		d.next = h.byteOrder.Uint32(block[pos : pos+4])
	}
	return d, nil
}

// resolveValue decodes one entry's value, following an offset when the value does not
// fit in the entry's own four value bytes.
//
// raw is the complete 12-byte directory entry, needed because the offset to an
// out-of-line value lives in its last four bytes.
func resolveValue(block []byte, h *tiffHeader, e *entry, raw []byte) error {
	size, ok := typeSize(e.typ)
	if !ok {
		return fmt.Errorf("exif: tag 0x%04x has unknown type %d", e.tag, e.typ)
	}
	total := int64(size) * int64(e.count)
	if total < 0 || total > int64(len(block)) {
		return fmt.Errorf("exif: tag 0x%04x declares %d bytes", e.tag, total)
	}

	// A value of at most four bytes is stored in the entry itself, in the order the
	// file's byte order declares.
	if total <= 4 {
		e.offset = -1
		e.bytes = append([]byte(nil), raw[8:8+int(total)]...)
		return decodeScalar(h, e, e.bytes)
	}

	off := h.byteOrder.Uint32(raw[8:12])
	if int64(off) < 0 || int64(off)+total > int64(len(block)) {
		return fmt.Errorf("exif: tag 0x%04x value at %d is outside the block", e.tag, off)
	}
	e.offset = int(off)
	e.bytes = block[off : int64(off)+total]
	return decodeScalar(h, e, e.bytes)
}

func typeSize(t uint16) (int, bool) {
	switch t {
	case typeByte, typeASCII, typeUndefined:
		return 1, true
	case typeShort:
		return 2, true
	case typeLong, typeSRational:
		return 4, true
	case typeRational:
		return 8, true
	}
	return 0, false
}

// decodeScalar turns an entry's bytes into a usable value.
//
// Only the shapes this module interprets are decoded. Anything else is left as bytes,
// which is better than guessing a type and producing a plausible wrong number.
func decodeScalar(h *tiffHeader, e *entry, b []byte) error {
	switch e.typ {
	case typeASCII:
		// An ASCII value is not NUL terminated when its length is exact, and is padded
		// with NULs when it is not. Both appear in the wild.
		s := string(b)
		s = strings.TrimRight(s, "\x00")
		if i := strings.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		e.value = strings.TrimSpace(s)
	case typeShort:
		if len(b) < 2 {
			return fmt.Errorf("exif: tag 0x%04x short value is truncated", e.tag)
		}
		if e.count == 1 {
			e.value = h.byteOrder.Uint16(b)
		} else {
			out := make([]uint16, 0, e.count)
			for i := 0; i+2 <= len(b); i += 2 {
				out = append(out, h.byteOrder.Uint16(b[i:i+2]))
			}
			e.value = out
		}
	case typeLong:
		if len(b) < 4 {
			return fmt.Errorf("exif: tag 0x%04x long value is truncated", e.tag)
		}
		if e.count == 1 {
			e.value = h.byteOrder.Uint32(b)
		} else {
			out := make([]uint32, 0, e.count)
			for i := 0; i+4 <= len(b); i += 4 {
				out = append(out, h.byteOrder.Uint32(b[i:i+4]))
			}
			e.value = out
		}
	case typeRational:
		if len(b) < 8 {
			return fmt.Errorf("exif: tag 0x%04x rational value is truncated", e.tag)
		}
		num := h.byteOrder.Uint32(b[0:4])
		den := h.byteOrder.Uint32(b[4:8])
		if e.count == 1 {
			e.value = rational(num, den)
		} else {
			out := make([]float64, 0, e.count)
			for i := 0; i+8 <= len(b); i += 8 {
				out = append(out, rational(h.byteOrder.Uint32(b[i:i+4]), h.byteOrder.Uint32(b[i+4:i+8])))
			}
			e.value = out
		}
	case typeSRational:
		if len(b) < 8 {
			return fmt.Errorf("exif: tag 0x%04x signed rational value is truncated", e.tag)
		}
		num := int32(h.byteOrder.Uint32(b[0:4]))
		den := int32(h.byteOrder.Uint32(b[4:8]))
		if e.count == 1 {
			e.value = float64(num) / float64(den)
		}
	case typeByte, typeUndefined:
		// Kept as bytes. A byte array is meaningful to some tags and meaningless to
		// others, and this module reads it only where it knows the meaning.
	}
	return nil
}

// rational divides, refusing a zero denominator.
//
// A zero denominator here is either a corrupt file or a camera writing an unset
// field, and returning infinity for it would propagate into a coordinate.
func rational(num, den uint32) float64 {
	if den == 0 {
		return 0
	}
	v := float64(num) / float64(den)
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return 0
	}
	return v
}

// degreesToDecimal converts a GPS triple in degrees, minutes, seconds to decimal
// degrees.
func degreesToDecimal(dms []float64) (float64, bool) {
	if len(dms) < 2 {
		return 0, false
	}
	d := dms[0]
	m := 0.0
	if len(dms) > 1 {
		m = dms[1]
	}
	s := 0.0
	if len(dms) > 2 {
		s = dms[2]
	}
	// A camera that has not resolved a fix writes zeros rather than omitting the tag,
	// so an all-zero triple means "no fix recorded" and must not become Null Island.
	if d == 0 && m == 0 && s == 0 {
		return 0, false
	}
	v := d + m/60 + s/3600
	if v < 0 {
		v = -v
	}
	if v > 180 {
		return 0, false
	}
	return v, true
}
