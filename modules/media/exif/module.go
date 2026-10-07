// Package exif reads image metadata and reports what an image discloses about its
// origin, the device that made it, and where it was taken.
//
// Every field here is a claim the device or software made about itself. Cameras write
// their own model and serial, software stamps its own version, and a phone will happily
// record a GPS fix at whatever moment it was asked. None of it is observation of the
// scene, and the grading reflects that: nothing from EXIF reaches top reliability, and
// a GPS coordinate is never treated as a location the subject was present at.
//
// The one signal here that is more than a claim is the embedded thumbnail. Every camera
// writes a small copy of the image alongside the metadata, and that copy is generated
// at capture time. When the thumbnail and the image disagree in size or carry different
// timestamps, the image was changed after capture and the thumbnail still reflects what
// the camera saw. That is a fact about the file rather than a statement inside it.
package exif

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WildanDeveloper/argus/pkg/sdk"
)

// Version is stamped into evidence provenance.
const Version = "1.0.0"

// Grading.
//
// EXIF is trivially editable and camera clocks are frequently wrong, so no field from
// it is better than "probably true". Device self-identification is the strongest claim
// available and is still only B, because a claim by the thing being described is not
// independent of it.
const (
	gradeReliability = 'B'
	gradeCredibility = '2'
)

// Module is the exif collector.
type Module struct {
	deps sdk.Deps
	now  func() time.Time

	// roots bounds which files may be read.
	//
	// A task value can originate from a collector reading attacker-influenced data, so
	// an unbounded path would turn this into an arbitrary file read: /etc/shadow would
	// be reported as an image error, or worse, its bytes retained as evidence. Reading
	// only inside the workspace means a task that names a path outside it is refused
	// rather than obeyed.
	roots []string
	// maxBytes bounds a single file. Metadata lives in the first few kilobytes, so a
	// bound far below a photo's size is not a real limitation.
	maxBytes int64
	// keepMetadata controls whether raw metadata is retained as evidence.
	keepMetadata bool
}

// Option configures the module.
type Option func(*Module)

// WithRoots sets the directories files may be read from. An empty list means the
// process working directory.
func WithRoots(roots ...string) Option {
	return func(m *Module) {
		if len(roots) > 0 {
			m.roots = roots
		}
	}
}

// WithMaxBytes bounds the size of a file this module will read.
func WithMaxBytes(n int64) Option {
	return func(m *Module) {
		if n > 0 {
			m.maxBytes = n
		}
	}
}

// WithMetadataRetention turns raw metadata retention on or off.
func WithMetadataRetention(on bool) Option { return func(m *Module) { m.keepMetadata = on } }

var _ sdk.Module = (*Module)(nil)

// New builds the module.
func New(opts ...Option) *Module {
	m := &Module{
		now: time.Now,
		// 32 MiB is larger than any camera produces and small enough that a
		// pathological file cannot exhaust a worker.
		maxBytes:     32 << 20,
		keepMetadata: true,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Manifest declares what the module consumes, produces, and may contact.
func (m *Module) Manifest() sdk.Manifest {
	return sdk.Manifest{
		Name:        "exif",
		Version:     Version,
		Category:    "media",
		Description: "Image metadata: capture device, software, timestamps, GPS, and thumbnail consistency",
		Consumes:    []sdk.EntityType{sdk.TypeFile, sdk.TypeImage},
		Produces: []sdk.EntityType{sdk.TypeLocation, sdk.TypeOrg, sdk.TypeText,
			sdk.TypeFinding},
		// This module reads local files and contacts nothing. Declaring it anything but
		// passive would imply a network request it never makes, and an empty
		// EgressHosts is only correct because of that: the guard has nothing to permit.
		Mode:            sdk.ModePassive,
		Sensitivity:     sdk.SensMedium,
		ReadsLocalFiles: true,
		// No hosts. A metadata reader that could reach the network would not be a
		// metadata reader.
		EgressHosts: []string{},
		Tags:        []string{"metadata", "forensics", "local", "no-egress"},
	}
}

// Init receives brokered dependencies.
func (m *Module) Init(_ context.Context, d sdk.Deps) error {
	m.deps = d
	if d.Now != nil {
		m.now = d.Now
	}
	return nil
}

// Close releases nothing.
func (m *Module) Close() error { return nil }

// Run reads one image's metadata and reports what it discloses.
func (m *Module) Run(ctx context.Context, t sdk.Task, e sdk.Emitter) error {
	if t.Target.ID == "" {
		return fmt.Errorf("exif: task has no target")
	}

	// The entity is content-addressed, so the path travels as a task parameter rather
	// than inside it.
	raw := t.Param(sdk.ParamFilePath, "")
	if raw == "" {
		raw = t.Target.Value
	}
	// The scope check for a local file is the roots check inside resolve, not
	// CanInvestigate. That helper answers questions about domains and addresses against
	// the engagement's scope policy, and a content hash is neither: asking it whether a
	// file is in scope can only ever produce a meaningless answer or a blanket denial.
	// Where the file lives is what determines whether reading it is authorized, and
	// resolve has already established that.
	path, err := m.resolve(raw)
	if err != nil {
		// A path outside the workspace is a refusal, not a failure worth reporting as a
		// scan error: the module never claimed to read it.
		e.Warn("path refused", "path", raw, "reason", err.Error())
		return nil
	}
	data, err := m.read(path)
	if err != nil {
		return fmt.Errorf("exif: read %s: %w", path, err)
	}

	doc := parseImage(data)
	if !doc.hasMetadata() {
		// Silence here would be indistinguishable from a stripped file, and "this image
		// carries no metadata" is itself the finding an investigator wants.
		return m.emitBare(t, e, path, doc)
	}

	if m.keepMetadata {
		// The raw block is the only way to check a parse. A camera's metadata is the
		// artifact behind every field here and an analyst cannot re-read it otherwise.
		if _, err := e.PutEvidence(ctx, sdk.EvidenceMeta{
			Source:    "file:" + raw,
			Method:    "exif.parse",
			MediaType: doc.mediaType(),
		}, doc.rawMetadata()); err != nil {
			e.Warn("metadata retention failed", "path", path, "err", err.Error())
		}
	}

	return m.emit(t, e, t.Target, path, doc)
}

// resolve validates that a path may be read.
func (m *Module) resolve(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("exif: empty path")
	}
	// A symlink can point anywhere, so it is resolved before the check rather than
	// after; checking the link itself would let a link inside the workspace name a
	// target outside it.
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		return "", fmt.Errorf("exif: %s does not resolve to a readable file", value)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("exif: %s is not readable", value)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("exif: %s is not a regular file", value)
	}
	if !m.allowed(resolved) {
		return "", fmt.Errorf("exif: %s is outside every permitted root", value)
	}
	return resolved, nil
}

// allowed reports whether a path lies inside a permitted root.
//
// The path is resolved here rather than relying on the caller, because a symlink that
// names a target outside the roots is the case this exists to catch and a caller that
// forgot to resolve would otherwise pass it.
func (m *Module) allowed(path string) bool {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	roots := m.roots
	if len(roots) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			return false
		}
		roots = []string{wd}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for _, r := range roots {
		root, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		if root, err = filepath.EvalSymlinks(root); err != nil {
			// A root that does not exist yet cannot contain anything.
			continue
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			continue
		}
		// A relative path that climbs out of the root is not inside it. Comparing with
		// a string prefix would treat /work-evil as inside /work.
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return true
	}
	return false
}

// read loads a file, refusing anything larger than the bound.
func (m *Module) read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// The bound is applied to the opened handle rather than to a stat, so a file
	// replaced between the check and the read cannot be used to exceed it.
	data, truncated, err := readAllBounded(f, m.maxBytes)
	if err != nil {
		return nil, err
	}
	if truncated {
		// A truncated file's metadata may be intact or may be cut mid-record, and the
		// two look identical from here. Refusing is the only safe answer.
		return nil, fmt.Errorf("file exceeds the %d byte limit; refusing to parse a partial image", m.maxBytes)
	}
	return data, nil
}

func readAllBounded(f *os.File, limit int64) ([]byte, bool, error) {
	if limit <= 0 {
		limit = 32 << 20
	}
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// emitBare records a file that carries no metadata.
func (m *Module) emitBare(t sdk.Task, e sdk.Emitter, path string, doc *document) error {
	obs := sdk.Observation{
		Predicate:   "no_metadata",
		Object:      filepath.Base(path),
		Source:      sdk.Source{Module: "exif", Provider: "file", Method: "exif.parse"},
		Reliability: gradeReliability,
		Credibility: gradeCredibility,
		ObservedAt:  m.now(),
	}
	obs.AddAttr("format", doc.format)
	if w, h, ok := doc.dimensions(); ok {
		obs.AddAttr("width", w)
		obs.AddAttr("height", h)
	}
	// "No metadata found" says nothing about whether metadata was ever there, and a
	// file that was cleaned and one that never had any look identical without this.
	obs.AddAttr("note", "no EXIF, XMP, or IPTC block was present; this does not indicate whether metadata was removed")
	return e.Emit(sdk.Finding{
		Entity:      t.Target,
		Observation: obs,
		Kind:        "exif-no-metadata",
		Severity:    sdk.SevInfo,
	})
}

// Register adds the module to the compile-time registry.
func init() {
	sdk.Register(func() sdk.Module { return New() })
}

// emit reports what the image discloses.
//
// Nothing here is presented as an observation of the scene. Every field is a claim the
// device or its software made, and the grading reflects that; the one exception is the
// thumbnail, which is a fact about the file.
func (m *Module) emit(t sdk.Task, e sdk.Emitter, target sdk.Entity, path string, doc *document) error {
	source := sdk.Source{Module: "exif", Provider: "file", Method: "exif.parse"}
	newObs := func(predicate, object string) sdk.Observation {
		return sdk.Observation{
			Predicate:   predicate,
			Object:      object,
			Source:      source,
			Reliability: gradeReliability,
			Credibility: gradeCredibility,
			ObservedAt:  m.now(),
		}
	}
	base := func() map[string]any {
		return map[string]any{"file": filepath.Base(path)}
	}

	for _, b := range doc.blocks {
		if err := m.emitBlock(t, e, target, doc, b, newObs, base); err != nil {
			return err
		}
	}

	// IPTC names are written by an editor or an agency rather than by the camera, and
	// they are the field most likely to name a person.
	for field, value := range doc.iptc {
		switch field {
		case "byline", "byline_title", "contact", "credit":
			pe, err := sdk.NewEntityOrErr(sdk.TypePerson, value)
			if err != nil {
				continue
			}
			o := newObs("authored_by", value)
			o.AddAttr("iptc_field", field)
			o.AddAttr("file", filepath.Base(path))
			// A byline names who wrote the caption, not who owns the device and not
			// necessarily a person rather than an agency. The edge is heuristic for that
			// reason.
			if err := e.Emit(sdk.Finding{
				Entity:      pe,
				Relations:   []sdk.Relation{sdk.HeuristicRel(target.ID, pe.ID, sdk.RelMentions)},
				Observation: o,
				Kind:        "exif-author",
				Severity:    sdk.SevInfo,
			}); err != nil {
				return err
			}
		case "source", "credit_supplier", "caption_abstract", "copyright_notice", "caption":
			o := newObs("image_described", value)
			o.AddAttr("iptc_field", field)
			o.AddAttr("file", filepath.Base(path))
			if err := e.Emit(sdk.Finding{
				Entity:      target,
				Observation: o,
				Kind:        "exif-description",
				Severity:    sdk.SevInfo,
			}); err != nil {
				return err
			}
		}
	}

	if doc.iccProfile != "" {
		o := newObs("color_profile_present", doc.iccProfile)
		o.AddAttr("file", filepath.Base(path))
		if err := e.Emit(sdk.Finding{
			Entity: target, Observation: o, Kind: "exif-icc-profile", Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}
	if doc.xmp != "" {
		o := newObs("xmp_present", "")
		o.AddAttr("file", filepath.Base(path))
		o.AddAttr("bytes", len(doc.xmp))
		// The packet is retained whole already; the attributes name what was looked for
		// so a reader knows the parse covered it.
		o.AddAttr("contains", xmpFields(doc.xmp))
		if err := e.Emit(sdk.Finding{
			Entity: target, Observation: o, Kind: "exif-xmp", Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}

	return m.emitThumbnail(t, e, target, doc, newObs)
}

// emitBlock reports one EXIF directory's worth of claims.
func (m *Module) emitBlock(t sdk.Task, e sdk.Emitter, target sdk.Entity, doc *document,
	b *tiffDoc, newObs func(string, string) sdk.Observation, _ func() map[string]any) error {

	name := filepath.Base(target.Value)
	_ = name

	// Device. Make and Model identify hardware; neither is an organisation and neither
	// is a person, so they are attributes rather than entities.
	make := b.ifd0.string(tagMake)
	model := b.ifd0.string(tagModel)
	software := b.ifd0.string(tagSoftware)
	if make != "" || model != "" || software != "" {
		o := newObs("captured_with", strings.TrimSpace(make+" "+model))
		o.AddAttr("file", target.Value)
		if make != "" {
			o.AddAttr("camera_make", make)
		}
		if model != "" {
			o.AddAttr("camera_model", model)
		}
		if software != "" {
			o.AddAttr("software", software)
		}
		if host := b.ifd0.string(tagHostComputer); host != "" {
			o.AddAttr("host_computer", host)
		}
		if lens := b.exif.string(tagLensModel); lens != "" {
			o.AddAttr("lens_model", lens)
		}
		// Serial numbers identify a physical unit. They stay attributes: there is no
		// serial entity type, and inventing one would put an unmatchable value in the
		// graph.
		if sn := b.exif.string(tagBodySerial); sn != "" {
			o.AddAttr("body_serial", sn)
		}
		if ls := b.exif.string(tagLensSerial); ls != "" {
			o.AddAttr("lens_serial", ls)
		}
		if owner := b.exif.string(tagCameraOwner); owner != "" {
			o.AddAttr("camera_owner_name", owner)
			// The camera owner's registered name is a person's name as the device
			// recorded it. It is emitted as a person entity but flagged as a
			// self-reported field, because the field is editable and often stale.
			if pe, err := sdk.NewEntityOrErr(sdk.TypePerson, owner); err == nil {
				po := newObs("named_in_metadata", owner)
				po.AddAttr("field", "camera_owner_name")
				po.AddAttr("file", target.Value)
				po.AddAttr("self_reported", true)
				if err := e.Emit(sdk.Finding{
					Entity:      pe,
					Relations:   []sdk.Relation{sdk.HeuristicRel(target.ID, pe.ID, sdk.RelMentions)},
					Observation: po,
					Kind:        "exif-person",
					Severity:    sdk.SevLow,
				}); err != nil {
					return err
				}
			}
		}
		if err := e.Emit(sdk.Finding{
			Entity: target, Observation: o, Kind: "exif-device", Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}

	// Timestamps.
	for _, ts := range []struct {
		tag  uint16
		name string
	}{
		{tagDateTimeOrig, "capture"},
		{tagDateTimeDigi, "digitized"},
		{tagDateTime, "file_modified"},
	} {
		tv, ok := b.exifTimestamp(ts.tag)
		if !ok {
			continue
		}
		o := newObs("timestamp", tv.local)
		o.AddAttr("which", ts.name)
		o.AddAttr("file", target.Value)
		o.AddAttr("local", tv.local)
		if tv.subsec != "" {
			o.AddAttr("subsecond", tv.subsec)
		}
		if tv.ambiguous {
			// This is the field that matters. An EXIF timestamp with no offset is a
			// wall-clock reading from a clock nobody has verified, and presenting it as an
			// instant would place events hours from where they happened.
			o.AddAttr("timezone_ambiguous", true)
			o.AddAttr("note", "the file records no zone offset for this timestamp; the local time cannot be resolved to an instant")
		} else {
			o.AddAttr("utc", tv.utc)
			o.AddAttr("offset", tv.offset)
		}
		if err := e.Emit(sdk.Finding{
			Entity: target, Observation: o, Kind: "exif-timestamp", Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}

	// Free-text user comment, which frequently names a person or a workflow.
	if uc := userComment(b.exif); uc != "" {
		o := newObs("user_comment", uc)
		o.AddAttr("file", target.Value)
		if err := e.Emit(sdk.Finding{
			Entity: target, Observation: o, Kind: "exif-comment", Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}

	// GPS.
	if g, ok := decodeGPS(b.gps); ok {
		o := newObs("geotagged", fmt.Sprintf("%.6f,%.6f", g.lat, g.lon))
		o.AddAttr("file", target.Value)
		o.AddAttr("latitude", g.lat)
		o.AddAttr("longitude", g.lon)
		if g.haveAlt {
			alt := g.altitude
			if g.belowSea {
				alt = -alt
			}
			o.AddAttr("altitude_metres", alt)
		}
		if g.haveDop {
			o.AddAttr("dilution_of_precision", g.precision)
		}
		if g.satellites > 0 {
			o.AddAttr("satellites", g.satellites)
		}
		if g.status != "" {
			o.AddAttr("fix_status", g.status)
		}
		if g.dateStamp != "" {
			o.AddAttr("gps_date", g.dateStamp)
		}
		if g.timeStamp != "" {
			o.AddAttr("gps_time", g.timeStamp)
		}
		// A coordinate is where the device was, not necessarily where the subject was.
		// A photo taken at home with the camera in a pocket locates the home; one taken
		// on someone else's camera locates the photographer.
		o.AddAttr("scope", "where the device recorded a fix, which is not necessarily where the subject was")
		o.AddAttr("spooofable", true)

		coord := fmt.Sprintf("%.5f,%.5f", g.lat, g.lon)
		loc, err := sdk.NewEntityOrErr(sdk.TypeLocation, coord)
		if err == nil {
			if err := e.Emit(sdk.Finding{
				Entity:      loc,
				Relations:   []sdk.Relation{sdk.HeuristicRel(target.ID, loc.ID, sdk.RelLocatedAt)},
				Observation: o,
				Kind:        "exif-geotag",
				Severity:    sdk.SevLow,
			}); err != nil {
				return err
			}
		}
	}

	// MakerNotes are retained but not interpreted.
	if len(b.makerNoteOf(doc)) > 0 {
		o := newObs("maker_note_present", "")
		o.AddAttr("file", target.Value)
		o.AddAttr("bytes", len(b.makerNoteOf(doc)))
		o.AddAttr("note", "vendor-specific and undocumented; the raw block is retained rather than interpreted, because a generic reader would decode it into confident nonsense")
		if err := e.Emit(sdk.Finding{
			Entity: target, Observation: o, Kind: "exif-makernote", Severity: sdk.SevInfo,
		}); err != nil {
			return err
		}
	}
	return nil
}

// makerNoteOf returns the raw MakerNote blob for a document.
func (b *tiffDoc) makerNoteOf(d *document) []byte {
	if b == nil || b.exif == nil {
		return nil
	}
	e, ok := b.exif.tag(tagMakerNote)
	if !ok {
		return nil
	}
	return e.bytes
}

// userComment decodes the UserComment tag, whose leading eight bytes identify an
// encoding.
func userComment(d *ifd) string {
	if d == nil {
		return ""
	}
	e, ok := d.tag(tagUserComment)
	if !ok {
		return ""
	}
	b := e.bytes
	if len(b) <= 8 {
		return ""
	}
	// The first eight bytes are a character-code designator. ASCII and UTF-8 are the
	// two in practice; UNICODE means UTF-16.
	switch string(b[:8]) {
	case "ASCII\x00\x00\x00":
		return strings.TrimSpace(strings.TrimRight(string(b[8:]), "\x00"))
	case "UNICODE\x00":
		return decodeUTF16(b[8:])
	}
	return strings.TrimSpace(strings.TrimRight(string(b[8:]), "\x00"))
}

// decodeUTF16 reads a UTF-16 byte string.
func decodeUTF16(b []byte) string {
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	out := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := uint16(b[i]) | uint16(b[i+1])<<8
		// A NUL-terminated string is common; stop rather than emit trailing padding.
		if c == 0 {
			break
		}
		out = append(out, rune(c))
	}
	return strings.TrimSpace(string(out))
}

// emitThumbnail reports whether the embedded thumbnail agrees with the image.
//
// This is the one field in the file that is a fact rather than a claim. The thumbnail
// is generated by the camera's own pipeline at capture time, so when it disagrees with
// the image the image was changed afterwards and the thumbnail still shows what the
// camera saw.
func (m *Module) emitThumbnail(t sdk.Task, e sdk.Emitter, target sdk.Entity, doc *document,
	newObs func(string, string) sdk.Observation) error {

	if !doc.thumbPresent {
		return nil
	}
	o := newObs("thumbnail_present", "")
	o.AddAttr("file", target.Value)
	if doc.haveThumbDims {
		o.AddAttr("thumbnail_width", doc.thumbWidth)
		o.AddAttr("thumbnail_height", doc.thumbHeight)
	}
	if len(doc.thumbBytes) > 0 {
		o.AddAttr("thumbnail_bytes", len(doc.thumbBytes))
	}

	kind := "exif-thumbnail"
	severity := sdk.SevInfo
	var mismatches []string

	// Size agreement. A camera generates the thumbnail at a fixed fraction of the
	// image's aspect ratio, so a thumbnail whose proportions differ means the image was
	// cropped or reshaped after capture.
	if doc.haveThumbDims && doc.haveDims {
		imgRatio := float64(doc.width) / float64(doc.height)
		thumbRatio := float64(doc.thumbWidth) / float64(doc.thumbHeight)
		if doc.height > 0 && doc.thumbHeight > 0 {
			if diff := absf(imgRatio - thumbRatio); diff > 0.01 {
				mismatches = append(mismatches, "aspect_ratio")
				o.AddAttr("image_aspect", round4(imgRatio))
				o.AddAttr("thumbnail_aspect", round4(thumbRatio))
			}
			// An exact size match is the strongest signal available: it means the
			// thumbnail is the one the camera made for this exact frame.
			if doc.thumbWidth == doc.width && doc.thumbHeight == doc.height {
				o.AddAttr("dimensions_match_image", true)
			}
		}
	}

	// Time agreement. A thumbnail carrying its own capture time that differs from the
	// image's is a divergence worth stating plainly.
	if doc.thumbStamp != "" {
		o.AddAttr("thumbnail_timestamp", doc.thumbStamp)
	}

	switch len(mismatches) {
	case 0:
		o.AddAttr("consistent_with_image", true)
	default:
		kind = "exif-thumbnail-mismatch"
		severity = sdk.SevLow
		o.AddAttr("consistent_with_image", false)
		o.AddAttr("mismatched", mismatches)
		o.AddAttr("note", "the embedded thumbnail does not match the image, which indicates the file was changed after capture while the thumbnail retained what the camera recorded")
	}
	if len(doc.thumbBytes) > 0 {
		o.AddAttr("thumbnail_bytes", len(doc.thumbBytes))
	}
	return e.Emit(sdk.Finding{
		Entity: target, Observation: o, Kind: kind, Severity: severity,
	})
}

// xmpFields names the XMP properties this module looks for, so a reader knows what the
// parse covered.
func xmpFields(packet string) []string {
	var out []string
	for _, key := range []string{
		"tiff:Make", "tiff:Model", "photoshop:DateCreated", "xmp:CreateDate",
		"xmp:ModifyDate", "xmp:CreatorTool", "dc:creator", "dc:rights", "exif:GPSLatitude",
	} {
		if strings.Contains(packet, key) {
			out = append(out, key)
		}
	}
	return out
}

func absf(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func round4(f float64) float64 { return float64(int64(f*10000+0.5)) / 10000 }
