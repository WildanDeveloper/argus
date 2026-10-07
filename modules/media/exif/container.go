package exif

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

// document is everything one image file discloses.
type document struct {
	format string

	// exif blocks, in the order they appeared.
	blocks []*tiffDoc
	// xmp holds the XMP packet when present.
	xmp string
	// iptc holds IPTC fields when present.
	iptc map[string]string
	// iccProfile is non-empty when an ICC profile is embedded.
	iccProfile string
	// makerNote is the raw MakerNote blob. It is not parsed: MakerNotes are vendor
	// specific, undocumented, and a generic reader produces confident nonsense. It is
	// retained so a vendor-aware reader can have it.
	makerNote []byte

	// raw collects the metadata bytes, which is what an analyst needs in order to check
	// any parse made from them.
	raw []byte

	// image dims from the container, which is independent of what the metadata claims.
	width, height int
	haveDims      bool

	// thumbnail information.
	thumbPresent  bool
	thumbWidth    int
	thumbHeight   int
	haveThumbDims bool
	thumbBytes    []byte
	thumbStamp    string
}

// tiffDoc is one parsed EXIF block with its sub-directories resolved.
type tiffDoc struct {
	head    *tiffHeader
	block   []byte
	ifd0    *ifd
	exif    *ifd
	gps     *ifd
	interop *ifd
	ifd1    *ifd
}

func (d *document) mediaType() string {
	switch d.format {
	case "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "tiff":
		return "image/tiff"
	}
	return "application/octet-stream"
}

func (d *document) hasMetadata() bool {
	return len(d.blocks) > 0 || d.xmp != "" || len(d.iptc) > 0 || d.iccProfile != ""
}

func (d *document) dimensions() (int, int, bool) { return d.width, d.height, d.haveDims }

func (d *document) rawMetadata() []byte { return d.raw }

// magic identifies the container format.
var magic = []struct {
	sig    []byte
	format string
}{
	{[]byte{0xFF, 0xD8, 0xFF}, "jpeg"},
	{[]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, "png"},
	{[]byte{'I', 'I', 0x2A, 0x00}, "tiff"},
	{[]byte{'M', 'M', 0x00, 0x2A}, "tiff"},
	{[]byte("<?xml"), "xmp"},
	{[]byte("<x:xmpmeta"), "xmp"},
}

// parseImage dispatches on the file's magic.
func parseImage(data []byte) *document {
	d := &document{format: "unknown"}
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8}):
		d.format = "jpeg"
		parseJPEG(data, d)
	case bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}):
		d.format = "png"
		parsePNG(data, d)
	case bytes.HasPrefix(data, []byte{'I', 'I', 0x2A, 0x00}) ||
		bytes.HasPrefix(data, []byte{'M', 'M', 0x00, 0x2A}):
		d.format = "tiff"
		parseTIFFDocument(data, d)
	case bytes.HasPrefix(data, []byte("<x:xmpmeta")) || bytes.HasPrefix(data, []byte("<?xml")):
		d.format = "xmp"
		d.xmp = string(data)
		d.raw = data
	}
	return d
}

// --- JPEG ---

// JPEG marker numbers this module cares about.
const (
	markerSOF0  = 0xC0 // and C1..CF except C4, C8, CC
	markerSOF3  = 0xC3
	markerSOF5  = 0xC5
	markerSOF6  = 0xC6
	markerSOF7  = 0xC7
	markerSOF9  = 0xC9
	markerSOF10 = 0xCA
	markerSOF11 = 0xCB
	markerSOF13 = 0xCD
	markerSOF14 = 0xCE
	markerSOF15 = 0xCF

	markerAPP1  = 0xE1
	markerAPP2  = 0xE2
	markerAPP13 = 0xED
	markerSOS   = 0xDA
)

// exifPrefix is the six bytes that introduce EXIF inside an APP1 segment.
var exifPrefix = []byte("Exif\x00\x00")

// xmpPrefix identifies an XMP packet inside APP1.
var xmpPrefix = []byte("http://ns.adobe.com/xap/1.0/\x00")

// photoshopPrefix introduces APP13 Photoshop resources.
var photoshopPrefix = []byte("Photoshop 3.0\x00")

func parseJPEG(data []byte, d *document) {
	pos := 2 // past SOI
	for pos+1 < len(data) {
		if data[pos] != 0xFF {
			// Not a marker: JPEG allows fill bytes, so skip to the next one rather than
			// giving up. A parser that stops here would lose every segment after the
			// first run of padding.
			pos++
			continue
		}
		for pos < len(data) && data[pos] == 0xFF {
			pos++
		}
		if pos >= len(data) {
			break
		}
		marker := data[pos]
		pos++

		// Standalone markers carry no length.
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			continue
		}
		if marker == markerSOS {
			// Entropy-coded data follows and is not metadata. Everything worth reading
			// appears before it in practice, and scanning past it would be scanning
			// compressed pixels.
			break
		}
		if pos+2 > len(data) {
			break
		}
		length := int(binary.BigEndian.Uint16(data[pos : pos+2]))
		if length < 2 || pos+length > len(data) {
			break
		}
		payload := data[pos+2 : pos+length]
		pos += length

		switch {
		case isSOF(marker) && len(payload) >= 5:
			// The frame header carries the real pixel dimensions, which is worth
			// preferring over anything the metadata claims.
			h := int(binary.BigEndian.Uint16(payload[1:3]))
			w := int(binary.BigEndian.Uint16(payload[3:5]))
			if w > 0 && h > 0 {
				d.width, d.height, d.haveDims = w, h, true
			}
		case marker == markerAPP1:
			switch {
			case bytes.HasPrefix(payload, exifPrefix):
				block := payload[len(exifPrefix):]
				d.raw = append(d.raw, block...)
				if doc := parseTIFFDocument(block, d); doc != nil {
					d.blocks = append(d.blocks, doc)
				}
			case bytes.HasPrefix(payload, xmpPrefix):
				d.xmp += string(payload[len(xmpPrefix):])
				d.raw = append(d.raw, payload...)
			}
		case marker == markerAPP2 && len(payload) > 12:
			// An ICC profile is a named chunk: "ICC_PROFILE\0" then a sequence number and
			// a total. Only the first chunk is retained, since reassembling them all is
			// work for a value nothing here interprets.
			if bytes.HasPrefix(payload, []byte("ICC_PROFILE\x00")) && len(payload) >= 14 {
				if payload[12] == 1 {
					d.iccProfile = "present"
				}
			}
		case marker == markerAPP13 && bytes.HasPrefix(payload, photoshopPrefix):
			parseIPTC(payload[len(photoshopPrefix):], d)
		}
	}
}

func isSOF(marker byte) bool {
	switch marker {
	case markerSOF0, markerSOF3, markerSOF5, markerSOF6, markerSOF7,
		markerSOF9, markerSOF10, markerSOF11, markerSOF13, markerSOF14, markerSOF15:
		return true
	}
	return false
}

// --- IPTC ---

// parseIPTC reads the 8BIM resource block that carries IIM datasets.
func parseIPTC(b []byte, d *document) {
	pos := 0
	for pos+12 <= len(b) {
		if !bytes.Equal(b[pos:pos+4], []byte("8BIM")) {
			return
		}
		id := binary.BigEndian.Uint16(b[pos+4 : pos+6])
		// The name is Pascal-style: one length byte then the characters, padded to an
		// even length.
		nameLen := int(b[pos+6])
		pos += 7
		if pos+nameLen > len(b) {
			return
		}
		pos += nameLen
		if (nameLen+1)%2 == 1 {
			pos++
		}
		if pos+4 > len(b) {
			return
		}
		size := int(binary.BigEndian.Uint32(b[pos : pos+4]))
		pos += 4
		if size < 0 || pos+size > len(b) {
			return
		}
		payload := b[pos : pos+size]
		pos += size
		if size%2 == 1 {
			pos++
		}

		// 0x0404 is the IPTC-IIM block. Its contents are a sequence of records, each
		// introduced by the 0x1C marker with a dataset number and a record version.
		if id != 0x0404 {
			continue
		}
		p := 0
		for p+5 <= len(payload) {
			if payload[p] != 0x1C {
				p++
				continue
			}
			dataset := payload[p+1]
			if payload[p+2] != 2 {
				// Record version 2 is the only one defined; anything else is a dialect
				// this reader does not know.
				p += 3
				continue
			}
			size := 0
			// A length of at most 32767 is stored in two bytes with the high bit set on
			// the first. Larger values use four, which no IIM field reaches.
			if p+5 <= len(payload) {
				size = int(binary.BigEndian.Uint16(payload[p+3:p+5]) & 0x7FFF)
			}
			p += 5
			if p+size > len(payload) {
				break
			}
			value := strings.TrimRight(string(payload[p:p+size]), "\x00")
			p += size
			if value != "" {
				if d.iptc == nil {
					d.iptc = map[string]string{}
				}
				if _, seen := d.iptc[iptcName(dataset)]; !seen {
					d.iptc[iptcName(dataset)] = value
				}
			}
		}
	}
}

func iptcName(dataset byte) string {
	switch dataset {
	case 0x05:
		return "title"
	case 0x07:
		return "edit_time"
	case 0x0A:
		return "urgency"
	case 0x0F:
		return "category"
	case 0x14:
		return "expiration"
	case 0x19:
		return "special_instructions"
	case 0x28:
		return "date_created"
	case 0x2A:
		return "time_created"
	case 0x37:
		return "date_digitized"
	case 0x3C:
		return "time_digitized"
	case 0x50:
		return "byline"
	case 0x55:
		return "byline_title"
	case 0x5A:
		return "credit"
	case 0x5E:
		return "source"
	case 0x64:
		return "copyright_notice"
	case 0x66:
		return "contact"
	case 0x69:
		return "caption"
	case 0x6E:
		return "caption_abstract"
	case 0x73:
		return "keywords"
	case 0x7A:
		return "credit_supplier"
	case 0x7D:
		return "urgency_editorial"
	}
	return "dataset_" + strconv.Itoa(int(dataset))
}

// --- PNG ---

// PNG chunk types this module cares about.
const (
	pngExif    = "eXIf"
	pngXMP     = "iTXt" // only when its keyword is XML:com.adobe.xmp
	pngRawXMP  = "zTXt"
	pngProfile = "iCCP"
	pngText    = "tEXt"
	pngIPTC    = "zTXt"
)

func parsePNG(data []byte, d *document) {
	pos := 8
	for pos+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		if length < 0 || int64(pos)+int64(8+length+4) > int64(len(data)) {
			return
		}
		typ := string(data[pos+4 : pos+8])
		payload := data[pos+8 : pos+8+length]
		pos += 8 + length + 4 // past the payload and the CRC

		switch typ {
		case "IHDR":
			if len(payload) >= 8 {
				w := int64(binary.BigEndian.Uint32(payload[0:4]))
				h := int64(binary.BigEndian.Uint32(payload[4:8]))
				if w > 0 && h > 0 {
					d.width, d.height, d.haveDims = int(w), int(h), true
				}
			}
		case pngExif:
			d.raw = append(d.raw, payload...)
			// The eXIf chunk carries a TIFF block with no prefix.
			if doc := parseTIFFDocument(payload, d); doc != nil {
				d.blocks = append(d.blocks, doc)
			}
		case pngText, pngXMP:
			// A tEXt chunk is keyword, NUL, text. Only the XMP keyword is interesting
			// here; others are arbitrary PNG text and are left alone.
			if i := bytes.IndexByte(payload, 0); i > 0 && string(payload[:i]) == "XML:com.adobe.xmp" {
				d.xmp += string(payload[i+1:])
				d.raw = append(d.raw, payload...)
			}
		case pngProfile:
			d.iccProfile = "present"
		}
		if typ == "IEND" {
			return
		}
	}
}

// --- TIFF ---

// parseTIFFDocument reads a TIFF block and its sub-directories.
func parseTIFFDocument(block []byte, d *document) *tiffDoc {
	head, err := parseTIFFHeader(block)
	if err != nil {
		return nil
	}
	doc := &tiffDoc{head: head, block: block}

	doc.ifd0, err = parseIFD(block, head, head.ifd0Offset)
	if err != nil {
		return nil
	}
	// The sub-directory offsets are tags like any other, and a file that points one
	// outside the block is skipped rather than followed.
	doc.exif = subIFD(block, head, doc.ifd0, tagExifIFD)
	doc.gps = subIFD(block, head, doc.ifd0, tagGPSIFD)
	doc.interop = subIFD(block, head, doc.exif, tagInteropIFD)
	// IFD1 is the thumbnail directory, reached through the first directory's link.
	if doc.ifd0.next != 0 {
		doc.ifd1, _ = parseIFD(block, head, doc.ifd0.next)
	}

	d.collectThumbnail(doc)
	return doc
}

func subIFD(block []byte, head *tiffHeader, parent *ifd, tag uint16) *ifd {
	if parent == nil {
		return nil
	}
	e, ok := parent.tag(tag)
	if !ok {
		return nil
	}
	// The sub-directory offset is a LONG, stored inline.
	off, ok := e.value.(uint32)
	if !ok {
		return nil
	}
	d, err := parseIFD(block, head, off)
	if err != nil {
		return nil
	}
	return d
}

// collectThumbnail records what the thumbnail directory says.
//
// The thumbnail is the one part of EXIF that is a fact about the file rather than a
// claim inside it: it is written at capture time by the camera's own pipeline.
func (d *document) collectThumbnail(doc *tiffDoc) {
	if doc == nil || doc.ifd1 == nil {
		return
	}

	// The existence of the directory is what says a camera wrote a thumbnail. Waiting
	// for the byte offset to appear would miss every file whose thumbnail is declared
	// without its data attached, which is not a rare shape.
	d.thumbPresent = true
	if w, ok := doc.ifd1.int(tagImageWidth); ok {
		d.thumbWidth = w
		d.haveThumbDims = true
	}
	if h, ok := doc.ifd1.int(tagImageLength); ok {
		d.thumbHeight = h
		d.haveThumbDims = true
	}
	// The thumbnail's own bytes are located by an offset relative to the start of the
	// TIFF block. The directory existing at all is what says a thumbnail was written.
	if e, ok := doc.ifd1.tag(tagJPEGOffset); ok {
		if off, ok := e.value.(uint32); ok {
			if ln, ok := doc.ifd1.int(tagJPEGLength); ok && ln > 0 {
				base := int(off)
				// In a JPEG the offsets are absolute in the file; in a bare TIFF they are
				// relative to the TIFF header. Which one is knowable from whether the
				// bytes at that offset look like a JPEG, so both are tried and the
				// implausible one is discarded.
				if base+ln <= len(doc.block) {
					if isJPEGAt(doc.block[base : base+ln]) {
						d.thumbBytes = doc.block[base : base+ln]
					}
				}
				if d.thumbBytes == nil {
					// The block is the file itself when it was read straight, so an offset
					// past its end means the pointer is relative to something else and no
					// bytes can be claimed.
					_ = base
				}
			}
		}
	}
	if doc.exif != nil {
		d.thumbStamp = doc.exif.string(tagDateTimeOrig)
	}
}

func isJPEGAt(b []byte) bool {
	return len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF
}
