package exif

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Fixtures are built byte by byte rather than checked in as binaries, because a checked
// -in image cannot be reviewed: a reviewer has to take that it says what its name says.
// Building them here makes every tag and offset inspectable in the test that uses it.

type tiffBuilder struct {
	buf bytes.Buffer
	// nextDir is the offset to write into IFD0's next-directory link, used to chain a
	// thumbnail directory after the first one.
	nextDirAt uint32
}

func newTIFF() *tiffBuilder {
	// Little-endian TIFF header with the first directory at offset 8.
	t := &tiffBuilder{}
	t.buf.Write([]byte{'I', 'I', 42, 0})
	t.buf.Write([]byte{8, 0, 0, 0})
	return t
}

type tiffEntry struct {
	tag   uint16
	typ   uint16
	count uint32
	// inline is the four value bytes for a short or long.
	inline []byte
	// data is written to the data area and referenced by offset.
	data []byte
}

func short(tag uint16, v uint16) tiffEntry {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:2], v)
	return tiffEntry{tag: tag, typ: typeShort, count: 1, inline: b}
}

func long(tag uint16, v uint32) tiffEntry {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b[0:4], v)
	return tiffEntry{tag: tag, typ: typeLong, count: 1, inline: b}
}

func rat(tag uint16, num, den uint32) tiffEntry {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:4], num)
	binary.LittleEndian.PutUint32(b[4:8], den)
	return tiffEntry{tag: tag, typ: typeRational, count: 1, data: b}
}

func rats(tag uint16, values [][2]uint32) tiffEntry {
	b := make([]byte, 0, len(values)*8)
	for _, v := range values {
		var pair [8]byte
		binary.LittleEndian.PutUint32(pair[0:4], v[0])
		binary.LittleEndian.PutUint32(pair[4:8], v[1])
		b = append(b, pair[:]...)
	}
	return tiffEntry{tag: tag, typ: typeRational, count: uint32(len(values)), data: b}
}

// ascii builds an ASCII entry. A value of at most four bytes, with its NUL, is stored
// inline in the entry itself, which is what the specification requires and what real
// files do. Writing every ASCII value out of line would parse correctly by accident in
// this builder and fail against any real camera.
func ascii(tag uint16, s string) tiffEntry {
	body := append([]byte(s), 0)
	if len(body) <= 4 {
		inline := make([]byte, 4)
		copy(inline, body)
		return tiffEntry{tag: tag, typ: typeASCII, count: uint32(len(body)), inline: inline}
	}
	return tiffEntry{tag: tag, typ: typeASCII, count: uint32(len(body)), data: body}
}

func undefined(tag uint16, b []byte) tiffEntry {
	return tiffEntry{tag: tag, typ: typeUndefined, count: uint32(len(b)), data: b}
}

// writeIFD appends a directory at the current position and returns its offset, writing
// any out-of-line values immediately after the entry table.
//
// Sub-directory offsets therefore have to be patched after the fact, which is why
// addSub returns the tag to set later.
func (t *tiffBuilder) writeIFD(entries []tiffEntry) uint32 {
	offset := uint32(t.buf.Len())
	var count [2]byte
	binary.LittleEndian.PutUint16(count[0:2], uint16(len(entries)))
	t.buf.Write(count[:])

	for _, e := range entries {
		var raw [12]byte
		binary.LittleEndian.PutUint16(raw[0:2], e.tag)
		binary.LittleEndian.PutUint16(raw[2:4], e.typ)
		binary.LittleEndian.PutUint32(raw[4:8], e.count)
		if len(e.data) > 0 {
			// The offset is patched once the layout is known, so a placeholder goes in
			// now. Zero is never mistaken for a real offset because the patch below
			// always overwrites it.
			t.buf.Write(raw[:])
			continue
		}
		copy(raw[8:12], e.inline)
		t.buf.Write(raw[:])
	}
	// No next directory.
	t.buf.Write([]byte{0, 0, 0, 0})

	for i, e := range entries {
		if len(e.data) == 0 {
			continue
		}
		pos := offset + 2 + uint32(i)*12 + 8
		binary.LittleEndian.PutUint32(t.buf.Bytes()[pos:pos+4], uint32(t.buf.Len()))
		t.buf.Write(e.data)
	}
	return offset
}

// patch sets a LONG entry's value once its offset is known.
//
// It panics on a bad index rather than writing anyway. A negative index computes a
// position before the directory being patched, and an earlier fixture did exactly that:
// it wrote the sub-directory offset over the TIFF header, and the block then failed to
// parse for reasons that pointed nowhere near the cause.
func (t *tiffBuilder) patch(ifdOffset uint32, index int, v uint32) {
	if index < 0 {
		panic("tiffBuilder.patch: no entry with that tag in the directory")
	}
	pos := ifdOffset + 2 + uint32(index)*12 + 8
	if int(pos)+4 > t.buf.Len() {
		panic("tiffBuilder.patch: position is past the end of the block")
	}
	binary.LittleEndian.PutUint32(t.buf.Bytes()[pos:pos+4], v)
}

// indexOf finds an entry's position so it can be patched.
func indexOf(entries []tiffEntry, tag uint16) int {
	for i, e := range entries {
		if e.tag == tag {
			return i
		}
	}
	return -1
}

func (t *tiffBuilder) bytes() []byte { return t.buf.Bytes() }

// chainNext points IFD0's next-directory link at a later directory, which is how a
// thumbnail directory is reached.
func (t *tiffBuilder) chainNext(ifdOffset uint32, entries int, target uint32) {
	pos := ifdOffset + 2 + uint32(entries)*12
	binary.LittleEndian.PutUint32(t.buf.Bytes()[pos:pos+4], target)
}

// --- JPEG assembly ---

func jpegSegment(marker byte, payload []byte) []byte {
	out := []byte{0xFF, marker, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)+2))
	return append(out, payload...)
}

// jpegFrame builds a JPEG whose frame header declares the given dimensions.
func jpegFrame(w, h int) []byte {
	payload := []byte{8}
	payload = append(payload, byte(h>>8), byte(h))
	payload = append(payload, byte(w>>8), byte(w))
	payload = append(payload, 1, 1, 0x11, 0)
	return jpegSegment(0xC0, payload)
}

// jpegWith assembles a complete-enough JPEG around the given APP1 payload.
func jpegWith(exifPayload []byte, w, h int) []byte {
	var out []byte
	out = append(out, 0xFF, 0xD8) // SOI
	app1 := append([]byte("Exif\x00\x00"), exifPayload...)
	out = append(out, jpegSegment(0xE1, app1)...)
	out = append(out, jpegFrame(w, h)...)
	// Start of scan, with no entropy data. The parser stops here, which is correct: the
	// pixels carry no metadata.
	out = append(out, 0xFF, 0xDA, 0x00, 0x02)
	return out
}

// --- fixtures ---

// fullRecord is a complete, realistic EXIF block: a camera, a lens, three timestamps
// with an offset on the original, a signed GPS fix in the southern hemisphere, and a
// user comment.
func fullRecord() []byte {
	t := newTIFF()

	// The header names IFD0 at offset 8, so IFD0 is written first and its sub-directory
	// pointers patched afterwards. Writing a sub-directory first would put it where the
	// header says IFD0 is, and the whole block would parse into the wrong directory.
	ifd0 := []tiffEntry{
		ascii(tagMake, "Canon"),
		ascii(tagModel, "EOS 5D Mark IV"),
		ascii(tagSoftware, "Adobe Photoshop 26.0 (Windows)"),
		ascii(tagArtist, "A. Photographer"),
		ascii(tagCopyright, "(c) 2026 A. Photographer"),
		ascii(tagHostComputer, "workstation-07"),
		ascii(tagDateTime, "2026:09:01 11:22:33"),
		long(tagExifIFD, 0),
		long(tagGPSIFD, 0),
	}
	ifd0Offset := t.writeIFD(ifd0)

	gpsEntries := []tiffEntry{
		ascii(tagGPSVersionID, "2.3.0.0"),
		ascii(tagGPSLatitudeRef, "S"),
		rats(tagGPSLatitude, [][2]uint32{{33, 1}, {52, 1}, {2952, 100}}),
		ascii(tagGPSLongitudeRef, "E"),
		rats(tagGPSLongitude, [][2]uint32{{151, 1}, {12, 1}, {3660, 100}}),
		rat(tagGPSAltitude, 4235, 10),
		short(tagGPSSatellites, 12),
		ascii(tagGPSDateStamp, "2026:08:14"),
		ascii(tagGPSProcessing, "GPS tagging is on"),
	}
	gpsOffset := t.writeIFD(gpsEntries)

	exifEntries := []tiffEntry{
		ascii(tagExifVersion, "0231"),
		ascii(tagDateTimeOrig, "2026:08:14 07:01:43"),
		ascii(tagOffsetOrig, "+10:00"),
		ascii(tagSubSecOrig, "125"),
		ascii(tagDateTimeDigi, "2026:08:14 07:02:10"),
		ascii(tagLensModel, "EF 24-70mm f/2.8L II USM"),
		ascii(tagBodySerial, "042051000537"),
		ascii(tagCameraOwner, "A. Photographer"),
		undefined(tagUserComment, append([]byte("ASCII\x00\x00\x00"), "unit test frame"...)),
		undefined(tagMakerNote, []byte{0x4D, 0x4D, 0x00, 0x2A, 0xDE, 0x01, 0x02}),
		short(tagPixelXDim, 4000),
		short(tagPixelYDim, 3000),
	}
	exifOffset := t.writeIFD(exifEntries)

	t.patch(ifd0Offset, indexOf(ifd0, tagExifIFD), exifOffset)
	t.patch(ifd0Offset, indexOf(ifd0, tagGPSIFD), gpsOffset)
	return t.bytes()
}

// southWestSydney is the coordinate fullRecord encodes, as a sanity check on the
// fixture itself.
// southWestSydney is the coordinate fullRecord encodes: 33 deg 52 min 29.52 sec south,
// 151 deg 12 min 36.6 sec east. Computed rather than guessed, since my first value here
// was wrong by a few hundred metres and the test would have been asserting nothing.
var southWestSydney = struct{ lat, lon float64 }{-33.87487, 151.21017}

// mismatchedRecord is a record whose thumbnail directory disagrees with the image.
//
// The thumbnail is 200x150 while the image is 4000x3000: same aspect ratio, different
// scale, which is normal. This variant instead declares a thumbnail with a different
// proportion, which is what an edit leaves behind.
func thumbnailRecord(thumbW, thumbH int) []byte {
	t := newTIFF()

	ifd0 := []tiffEntry{
		ascii(tagMake, "Canon"),
		ascii(tagModel, "EOS 5D Mark IV"),
		long(tagExifIFD, 0),
	}
	ifd0Offset := t.writeIFD(ifd0)

	exifEntries := []tiffEntry{
		ascii(tagExifVersion, "0231"),
		ascii(tagDateTimeOrig, "2026:08:14 07:01:43"),
	}
	exifOffset := t.writeIFD(exifEntries)
	t.patch(ifd0Offset, indexOf(ifd0, tagExifIFD), exifOffset)

	// The thumbnail directory, reached through IFD0's next-directory link.
	ifd1 := []tiffEntry{
		short(tagImageWidth, uint16(thumbW)),
		short(tagImageLength, uint16(thumbH)),
	}
	ifd1Offset := t.writeIFD(ifd1)

	// The thumbnail directory is reached through IFD0's next-directory link.
	t.chainNext(ifd0Offset, len(ifd0), ifd1Offset)
	return t.bytes()
}

// minimalRecord carries a device and nothing else, which is the common case for a file
// that has been through an editor.
func minimalRecord() []byte {
	t := newTIFF()
	ifd0 := []tiffEntry{
		ascii(tagMake, "Apple"),
		ascii(tagModel, "iPhone 15 Pro"),
	}
	t.writeIFD(ifd0)
	return t.bytes()
}

// naiveTimestampRecord records a capture time with no zone offset at all, which is what
// every camera before the offset tags produced.
func naiveTimestampRecord() []byte {
	t := newTIFF()
	// IFD0 first, because the TIFF header names it at offset 8. Writing the Exif
	// directory first would place it where IFD0 is declared and the block would parse
	// into the wrong directory entirely.
	ifd0 := []tiffEntry{long(tagExifIFD, 0)}
	ifd0Offset := t.writeIFD(ifd0)

	exifEntries := []tiffEntry{
		ascii(tagDateTimeOrig, "2026:08:14 07:01:43"),
	}
	exifOffset := t.writeIFD(exifEntries)

	t.patch(ifd0Offset, indexOf(ifd0, tagExifIFD), exifOffset)
	return t.bytes()
}

// nullIslandRecord has a GPS block whose coordinates are all zero, which is what a
// device writes when it has no fix.
func nullIslandRecord() []byte {
	t := newTIFF()
	gpsEntries := []tiffEntry{
		ascii(tagGPSLatitudeRef, "N"),
		rats(tagGPSLatitude, [][2]uint32{{0, 1}, {0, 1}, {0, 1}}),
		ascii(tagGPSLongitudeRef, "E"),
		rats(tagGPSLongitude, [][2]uint32{{0, 1}, {0, 1}, {0, 1}}),
	}
	gpsOffset := t.writeIFD(gpsEntries)
	ifd0 := []tiffEntry{long(tagGPSIFD, 0)}
	ifd0Offset := t.writeIFD(ifd0)
	t.patch(ifd0Offset, indexOf(ifd0, tagGPSIFD), gpsOffset)
	return t.bytes()
}

// zeroDenominatorRecord divides by zero, which is how an unset rational is sometimes
// written.
func zeroDenominatorRecord() []byte {
	t := newTIFF()
	gpsEntries := []tiffEntry{
		ascii(tagGPSLatitudeRef, "N"),
		rats(tagGPSLatitude, [][2]uint32{{51, 0}, {30, 0}, {0, 0}}),
		ascii(tagGPSLongitudeRef, "W"),
		rats(tagGPSLongitude, [][2]uint32{{0, 1}, {7, 1}, {0, 100}}),
	}
	gpsOffset := t.writeIFD(gpsEntries)
	ifd0 := []tiffEntry{long(tagGPSIFD, 0)}
	ifd0Offset := t.writeIFD(ifd0)
	t.patch(ifd0Offset, indexOf(ifd0, tagGPSIFD), gpsOffset)
	return t.bytes()
}

// truncatedRecord is a TIFF block that stops mid-directory, which is what a file cut at
// a block boundary looks like.
func truncatedRecord() []byte {
	full := fullRecord()
	return full[:14]
}

// hugeCountRecord declares a directory with more entries than could fit.
func hugeCountRecord() []byte {
	var out bytes.Buffer
	out.Write([]byte{'I', 'I', 42, 0, 8, 0, 0, 0})
	out.Write([]byte{0xFF, 0xFF}) // 65535 entries in a 16 byte block
	return out.Bytes()
}

// TestFixturesAreSelfConsistent guards the fixtures themselves. A fixture that does not
// encode what its name says would make every assertion below it pass or fail for the
// wrong reason.
func TestFixturesAreSelfConsistent(t *testing.T) {
	d := parseImage(jpegWith(fullRecord(), 4000, 3000))
	g, ok := decodeGPS(d.blocks[0].gps)
	if !ok {
		t.Fatal("the GPS fixture did not decode")
	}
	if absf(g.lat-southWestSydney.lat) > 0.001 || absf(g.lon-southWestSydney.lon) > 0.001 {
		t.Errorf("fixture coordinate = %.5f,%.5f, want %.5f,%.5f",
			g.lat, g.lon, southWestSydney.lat, southWestSydney.lon)
	}
	if g.satellites != 12 {
		t.Errorf("fixture satellites = %d", g.satellites)
	}
}
