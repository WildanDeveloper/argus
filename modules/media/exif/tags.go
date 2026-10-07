package exif

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// EXIF, IPTC, and XMP tags this module interprets.
//
// Only tags whose meaning is fixed by the specification are listed. MakerNotes are
// deliberately absent: they are vendor specific, undocumented, and a generic reader
// that decodes them produces confident nonsense. The raw MakerNote is retained instead,
// so a vendor-aware reader can have it without this one guessing.
const (
	// IFD0 and ExifIFD.
	tagImageDescription = 0x010E
	tagMake             = 0x010F
	tagModel            = 0x0110
	tagArtist           = 0x013B
	tagCopyright        = 0x8298
	tagImageWidth       = 0x0100
	tagImageLength      = 0x0101
	tagSoftware         = 0x0131
	tagHostComputer     = 0x013C

	tagExifIFD      = 0x8769
	tagGPSIFD       = 0x8825
	tagInteropIFD   = 0xA005
	tagExifVersion  = 0x9000
	tagDateTime     = 0x0132 // DateTime, in IFD0
	tagDateTimeOrig = 0x9003
	tagDateTimeDigi = 0x9004
	tagOffsetTime   = 0x9010
	tagOffsetOrig   = 0x9011
	tagOffsetDigi   = 0x9012
	tagSubSecOrig   = 0x9291
	tagUserComment  = 0x9286
	tagMakerNote    = 0x927C
	tagCameraOwner  = 0xA430
	tagBodySerial   = 0xA431
	tagPixelXDim    = 0xA002
	tagPixelYDim    = 0xA003
	tagLensModel    = 0xA434
	tagLensSerial   = 0xA435

	// Thumbnail directory, IFD1.
	tagJPEGOffset = 0x0201
	tagJPEGLength = 0x0202

	// GPS directory.
	tagGPSVersionID       = 0x0000
	tagGPSLatitudeRef     = 0x0001
	tagGPSLatitude        = 0x0002
	tagGPSLongitudeRef    = 0x0003
	tagGPSLongitude       = 0x0004
	tagGPSAltitudeRef     = 0x0005
	tagGPSAltitude        = 0x0006
	tagGPSTimeStamp       = 0x0007
	tagGPSSatellites      = 0x0008
	tagGPSStatus          = 0x0009
	tagGPSMeasureMode     = 0x000A
	tagGPSDOP             = 0x000A
	tagGPSDateStamp       = 0x001D
	tagGPSProcessing      = 0x001B
	tagGPSAreaInformation = 0x001C
)

// gps is a decoded coordinate.
type gps struct {
	lat, lon float64
	// altitude is in metres. A reference of 1 means below sea level.
	altitude   float64
	haveAlt    bool
	belowSea   bool
	precision  float64
	satellites int
	status     string
	dateStamp  string
	timeStamp  string
	haveDop    bool
	method     string
}

// decodeGPS reads the GPS directory.
//
// The reference characters carry the hemisphere and are the only place it is recorded,
// so they are read before the numbers: dropping them turns every coordinate in the
// southern or western hemisphere into its positive counterpart.
func decodeGPS(d *ifd) (gps, bool) {
	if d == nil {
		return gps{}, false
	}
	latRef := strings.TrimSpace(d.string(tagGPSLatitudeRef))
	lonRef := strings.TrimSpace(d.string(tagGPSLongitudeRef))

	lat, latOK := rationalsOf(d, tagGPSLatitude)
	lon, lonOK := rationalsOf(d, tagGPSLongitude)
	if !latOK || !lonOK {
		return gps{}, false
	}
	latDec, ok := degreesToDecimal(lat)
	if !ok {
		return gps{}, false
	}
	lonDec, ok := degreesToDecimal(lon)
	if !ok {
		return gps{}, false
	}

	switch strings.ToUpper(latRef) {
	case "S":
		latDec = -latDec
	case "", "N":
	default:
		// An unrecognised hemisphere means the field is not usable, and assuming north
		// would silently misplace half the world's photographs.
		return gps{}, false
	}
	switch strings.ToUpper(lonRef) {
	case "W":
		lonDec = -lonDec
	case "", "E":
	default:
		return gps{}, false
	}
	if latDec < -90 || latDec > 90 || lonDec < -180 || lonDec > 180 {
		return gps{}, false
	}

	g := gps{lat: latDec, lon: lonDec, method: strings.TrimSpace(d.string(tagGPSProcessing))}
	if alt, ok := rationalsOf(d, tagGPSAltitude); ok && len(alt) > 0 {
		g.altitude = alt[0]
		g.haveAlt = true
	}
	if ref, ok := d.int(tagGPSAltitudeRef); ok && ref == 1 {
		g.belowSea = true
	}
	if v, ok := d.int(tagGPSSatellites); ok {
		g.satellites = v
	}
	g.status = strings.TrimSpace(d.string(tagGPSStatus))
	g.dateStamp = strings.TrimSpace(d.string(tagGPSDateStamp))
	if ts, ok := rationalsOf(d, tagGPSTimeStamp); ok && len(ts) >= 3 {
		g.timeStamp = fmtHMS(ts)
	}
	return g, true
}

// rationalsOf extracts a rational array, which is how GPS degrees are stored.
func rationalsOf(d *ifd, tag uint16) ([]float64, bool) {
	e, ok := d.tag(tag)
	if !ok {
		return nil, false
	}
	switch v := e.value.(type) {
	case []float64:
		return v, len(v) > 0
	case float64:
		return []float64{v}, true
	}
	return nil, false
}

// timestamp is one decoded EXIF time.
type timestamp struct {
	// local is the wall-clock time as recorded, with no zone applied.
	local string
	// utc is the same instant resolved through the recorded offset, when one exists.
	utc string
	// offset is the recorded zone offset, empty when the file did not state one.
	offset string
	// subsec is the sub-second field, when present.
	subsec string
	// ambiguous is true when the file recorded no offset.
	//
	// This is not a formality. EXIF timestamps are naive, and a camera whose clock was
	// never set, or set to the wrong zone, records a perfectly well-formed time that is
	// simply wrong. Presenting such a value as an instant without saying so is how an
	// image ends up placing an event hours away from where it happened.
	ambiguous bool
}

// decodeTimestamp reads a date and its zone offset.
//
// The two are separate tags in the Exif directory and a file may have either, both, or
// neither. Cameras that predate the offset tags never have one, which is most of them.
func decodeTimestamp(d *ifd, dateTag, offsetTag uint16) (timestamp, bool) {
	if d == nil {
		return timestamp{}, false
	}
	raw := strings.TrimSpace(d.string(dateTag))
	if raw == "" {
		return timestamp{}, false
	}
	ts := timestamp{local: raw}
	ts.subsec = strings.TrimSpace(d.string(tagSubSecOrig))
	if offsetTag != 0 {
		ts.offset = strings.TrimSpace(d.string(offsetTag))
	}
	if ts.offset != "" {
		ts.utc, ts.ambiguous = resolveWithOffset(raw, ts.offset)
	} else {
		ts.ambiguous = true
	}
	return ts, true
}

// exifTimestamp reads a timestamp from whichever directory holds it.
func (b *tiffDoc) exifTimestamp(dateTag uint16) (timestamp, bool) {
	if b.exif != nil {
		var offsetTag uint16
		switch dateTag {
		case tagDateTimeOrig:
			offsetTag = tagOffsetOrig
		case tagDateTimeDigi:
			offsetTag = tagOffsetDigi
		}
		if ts, ok := decodeTimestamp(b.exif, dateTag, offsetTag); ok {
			if ts.subsec == "" && b.interop != nil {
				ts.subsec = strings.TrimSpace(b.interop.string(tagSubSecOrig))
			}
			return ts, true
		}
	}
	if b.ifd0 != nil {
		// DateTime is in IFD0 with no offset tag of its own, which is itself the reason
		// it is the least reliable of the three.
		if ts, ok := decodeTimestamp(b.ifd0, tagDateTime, 0); ok {
			return ts, true
		}
	}
	return timestamp{}, false
}

// resolveWithOffset converts a naive EXIF time plus a zone offset into an instant.
//
// An offset that does not parse leaves the value ambiguous rather than being dropped:
// a wrong instant is worse than an admitted unknown, and the local time is still
// readable.
func resolveWithOffset(local, offset string) (string, bool) {
	t, ok := parseExifTime(local)
	if !ok {
		return "", true
	}
	sign := 1
	switch {
	case strings.HasPrefix(offset, "-"):
		sign = -1
		offset = offset[1:]
	case strings.HasPrefix(offset, "+"):
		offset = offset[1:]
	}
	// The offset is written "+HH:MM". The colon has to be accounted for: reading the
	// first two characters and the next two as digits turns "+10:00" into 10 and an
	// unparseable ":0", so every offset silently fails and every timestamp stays
	// ambiguous.
	digits := make([]byte, 0, 4)
	for i := 0; i < len(offset) && len(digits) < 4; i++ {
		if offset[i] >= '0' && offset[i] <= '9' {
			digits = append(digits, offset[i])
		}
	}
	if len(digits) != 4 {
		return "", true
	}
	hh, err1 := atoiSafe(string(digits[0:2]))
	mm, err2 := atoiSafe(string(digits[2:4]))
	if err1 != nil || err2 != nil || hh > 14 || mm > 59 {
		return "", true
	}
	shift := sign * (hh*3600 + mm*60)
	return t.Add(-time.Duration(shift) * time.Second).Format("2006-01-02T15:04:05Z07:00"), false
}

// exifTimeLayout is the one timestamp layout EXIF specifies: "YYYY:MM:DD HH:MM:SS",
// with no zone at all.
const exifTimeLayout = "2006:01:02 15:04:05"

// parseExifTime reads a naive EXIF timestamp.
//
// Cameras vary: some write a zone into the field itself, some write fractional
// seconds, and some write milliseconds. The strict layout is tried first so a
// well-formed value is never reinterpreted, and the looser ones only after it.
func parseExifTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(exifTimeLayout, s); err == nil {
		return t, true
	}
	for _, layout := range []string{
		"2006:01:02 15:04:05.000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// fmtHMS renders a GPS timestamp triple as HH:MM:SS.
func fmtHMS(parts []float64) string {
	if len(parts) < 3 {
		return ""
	}
	h := int(parts[0])
	mi := int(parts[1])
	sec := parts[2]
	if h < 0 || mi < 0 || sec < 0 {
		return ""
	}
	return fmt.Sprintf("%02d:%02d:%06.3f", h, mi, sec)
}

// atoiSafe parses a decimal integer, refusing anything that is not digits.
func atoiSafe(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("exif: empty number")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("exif: %q is not a number", s)
	}
	return n, nil
}
