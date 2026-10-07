package exif

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WildanDeveloper/argus/pkg/sdk"
	"github.com/WildanDeveloper/argus/pkg/sdktest"
)

// writeImage puts bytes in a temporary file inside the harness directory.
func writeImage(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// harness builds a module whose only permitted root is the test's temporary directory,
// which is what makes the path restriction meaningful rather than incidental.
func harness(t *testing.T, opts ...Option) (*sdktest.Harness, string) {
	t.Helper()
	dir := t.TempDir()
	all := append([]Option{WithRoots(dir)}, opts...)
	return sdktest.NewHarness(t, New(all...)), dir
}

// runFile runs the module against a local file.
//
// The target is content-addressed, exactly as the SDK requires, and the path travels as
// the task parameter. Building the entity from the path instead would be the mistake
// this test exists to make visible.
func runFile(t *testing.T, h *sdktest.Harness, path string) {
	t.Helper()
	sum := sha256.Sum256([]byte(path))
	ent := sdk.NewEntity(sdk.TypeFile, hex.EncodeToString(sum[:]))
	if ent.ID == "" {
		t.Fatalf("a content-addressed file entity was not constructed from %x", sum)
	}
	task := sdk.Task{Target: ent, Params: map[string]string{sdk.ParamFilePath: path}}
	if err := h.RunTask(task); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestManifestDeclaresNoHosts(t *testing.T) {
	man := New().Manifest()
	// This module reads local files and contacts nothing. An empty EgressHosts is
	// correct precisely because of that, and it would be wrong the moment a metadata
	// reader could reach the network.
	if len(man.EgressHosts) != 0 {
		t.Errorf("EgressHosts = %v, want empty: the module makes no requests", man.EgressHosts)
	}
	if man.Mode != sdk.ModePassive {
		t.Errorf("mode = %v, want passive", man.Mode)
	}
	if problems := sdk.ValidateManifest(man); len(problems) > 0 {
		t.Errorf("manifest problems: %v", problems)
	}
	// Image metadata names people and places, so its sensitivity is above the low
	// default even though nothing leaves the machine.
	if man.Sensitivity != sdk.SensMedium {
		t.Errorf("sensitivity = %v, want medium", man.Sensitivity)
	}
}

func TestReadsDeviceAndSoftware(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))

	runFile(t, h, path)

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Kind == "exif-device" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no device observation emitted")
	}
	if attrs["camera_make"] != "Canon" || attrs["camera_model"] != "EOS 5D Mark IV" {
		t.Errorf("device = %v", attrs)
	}
	if attrs["software"] != "Adobe Photoshop 26.0 (Windows)" {
		t.Errorf("software = %v; a version string is exactly the kind of thing this discloses",
			attrs["software"])
	}
	if attrs["lens_model"] == nil || attrs["body_serial"] == nil {
		t.Errorf("lens or serial missing: %v", attrs)
	}
}

func TestSerialNumbersStayAttributes(t *testing.T) {
	// There is no serial entity type. Inventing one would put a value in the graph
	// that nothing can match against.
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	for _, f := range h.Out.Findings {
		if f.Entity.Type == sdk.TypeText && strings.Contains(f.Entity.Value, "042051000537") {
			t.Error("a camera serial became an entity rather than an attribute")
		}
	}
}

func TestGPSIsDecodedWithItsHemisphere(t *testing.T) {
	// The reference characters are the only place the hemisphere is recorded. Dropping
	// them turns every photograph in the southern and western hemispheres into its
	// positive counterpart.
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Kind == "exif-geotag" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("no geotag emitted for a record carrying GPS")
	}
	lat, _ := attrs["latitude"].(float64)
	lon, _ := attrs["longitude"].(float64)
	if absf(lat-southWestSydney.lat) > 0.001 {
		t.Errorf("latitude = %v, want %v; the southern hemisphere needs a negative",
			lat, southWestSydney.lat)
	}
	if absf(lon-southWestSydney.lon) > 0.001 {
		t.Errorf("longitude = %v, want %v", lon, southWestSydney.lon)
	}
	if attrs["satellites"] != 12 {
		t.Errorf("satellites = %v", attrs["satellites"])
	}
}

func TestGPSIsStatedAsTheDeviceNotTheSubject(t *testing.T) {
	// A coordinate records where the device was. A photo taken at home with the camera
	// in a pocket locates the home; one taken on someone else's camera locates the
	// photographer. Neither is the subject being there.
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	for _, f := range h.Out.Findings {
		if f.Kind != "exif-geotag" {
			continue
		}
		scope, _ := f.Observation.Attrs["scope"].(string)
		if !strings.Contains(scope, "not necessarily where the subject was") {
			t.Errorf("scope = %q", scope)
		}
		if f.Observation.Attrs["spooofable"] != true {
			t.Error("a GPS fix is not flagged as spoofable, and it is trivially editable")
		}
		// The edge must be heuristic: a coordinate is not a confirmed association.
		for _, r := range f.Relations {
			if r.Type == sdk.RelLocatedAt && !r.Heuristic {
				t.Error("the geotag edge is not flagged heuristic")
			}
		}
	}
}

func TestNullIslandIsNotACoordinate(t *testing.T) {
	// A device with no fix writes zeros rather than omitting the tag. Reporting that as
	// a position puts the file at 0,0, which is a real place in the Atlantic.
	h, dir := harness(t)
	path := writeImage(t, dir, "nofix.jpg", jpegWith(nullIslandRecord(), 4000, 3000))
	runFile(t, h, path)

	for _, f := range h.Out.Findings {
		if f.Kind == "exif-geotag" {
			t.Error("an all-zero GPS block was reported as a position")
		}
	}
	if h.CountEntities(sdk.TypeLocation) != 0 {
		t.Error("a location entity was created from an unset GPS block")
	}
}

func TestZeroDenominatorDoesNotProduceNonsense(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "bad.jpg", jpegWith(zeroDenominatorRecord(), 4000, 3000))
	runFile(t, h, path)

	for _, f := range h.Out.Findings {
		if f.Kind != "exif-geotag" {
			continue
		}
		lat, _ := f.Observation.Attrs["latitude"].(float64)
		if lat != 0 || absf(lat) > 90 {
			t.Errorf("latitude = %v from a zero denominator", lat)
		}
	}
}

func TestTimestampWithOffsetResolvesToAnInstant(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	var got map[string]any
	for _, f := range h.Out.Findings {
		if f.Kind == "exif-timestamp" && f.Observation.Attrs["which"] == "capture" {
			got = f.Observation.Attrs
		}
	}
	if got == nil {
		t.Fatal("no capture timestamp emitted")
	}
	if got["timezone_ambiguous"] != nil {
		t.Error("a record carrying an offset was marked ambiguous")
	}
	// 07:01:43 at +10:00 is 21:01:43 the previous day in UTC.
	utc, _ := got["utc"].(string)
	if !strings.HasPrefix(utc, "2026-08-13T21:01:43") {
		t.Errorf("utc = %q, want 2026-08-13T21:01:43", utc)
	}
}

func TestNaiveTimestampIsMarkedAmbiguous(t *testing.T) {
	// EXIF timestamps are naive and camera clocks are frequently wrong. Presenting such
	// a value as an instant would place events hours from where they happened.
	h, dir := harness(t)
	path := writeImage(t, dir, "naive.jpg", jpegWith(naiveTimestampRecord(), 4000, 3000))
	runFile(t, h, path)

	var got map[string]any
	for _, f := range h.Out.Findings {
		if f.Kind == "exif-timestamp" {
			got = f.Observation.Attrs
		}
	}
	if got == nil {
		t.Fatal("no timestamp emitted")
	}
	if got["timezone_ambiguous"] != true {
		t.Errorf("a timestamp with no offset was not marked ambiguous: %v", got)
	}
	if _, hasUTC := got["utc"]; hasUTC {
		t.Error("an instant was published for a timestamp that carries no offset")
	}
	if note, _ := got["note"].(string); !strings.Contains(note, "cannot be resolved to an instant") {
		t.Errorf("note = %q", note)
	}
}

func TestSubSecondIsRecorded(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	for _, f := range h.Out.Findings {
		if f.Kind == "exif-timestamp" && f.Observation.Attrs["which"] == "capture" {
			if f.Observation.Attrs["subsecond"] != "125" {
				t.Errorf("subsecond = %v", f.Observation.Attrs["subsecond"])
			}
			return
		}
	}
	t.Error("no capture timestamp with a sub-second field")
}

func TestMakerNoteIsRetainedNotInterpreted(t *testing.T) {
	// MakerNotes are vendor specific and undocumented. A generic reader that decoded them
	// would produce confident nonsense, so the raw block is kept and nothing is claimed
	// about it.
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	var found bool
	for _, f := range h.Out.Findings {
		if f.Kind != "exif-makernote" {
			continue
		}
		found = true
		if n, _ := f.Observation.Attrs["bytes"].(int); n == 0 {
			t.Error("no MakerNote bytes reported")
		}
		if note, _ := f.Observation.Attrs["note"].(string); !strings.Contains(note, "confident nonsense") {
			t.Errorf("note = %q", note)
		}
	}
	if !found {
		t.Fatal("the MakerNote was not reported at all")
	}
}

func TestUserCommentIsDecoded(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	for _, f := range h.Out.Findings {
		if f.Kind == "exif-comment" && f.Observation.Object != "unit test frame" {
			t.Errorf("comment = %v", f.Observation.Object)
			return
		}
		if f.Kind == "exif-comment" {
			return
		}
	}
	t.Error("no user comment emitted")
}

func TestCameraOwnerIsAPersonAndFlaggedSelfReported(t *testing.T) {
	// The registered owner name is a person as the device recorded it. The field is
	// editable and often stale, so it says so.
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	h.AssertEntities(sdk.TypePerson, "A. Photographer")

	for _, f := range h.Out.Findings {
		if f.Kind != "exif-person" {
			continue
		}
		if f.Observation.Attrs["self_reported"] != true {
			t.Error("a self-reported name is not flagged as such")
		}
		for _, r := range f.Relations {
			if !r.Heuristic {
				t.Error("the person edge is not flagged heuristic")
			}
		}
	}
}

func TestThumbnailAgreementIsReported(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "thumb.jpg", jpegWith(thumbnailRecord(160, 120), 4000, 3000))
	runFile(t, h, path)

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if strings.HasPrefix(f.Kind, "exif-thumbnail") {
			attrs = f.Observation.Attrs
			if attrs["consistent_with_image"] != true {
				t.Errorf("a proportional thumbnail was reported as inconsistent: %v", attrs)
			}
			return
		}
	}
	t.Fatal("no thumbnail observation emitted")
}

func TestThumbnailMismatchIsRaised(t *testing.T) {
	// The thumbnail is written by the camera's own pipeline at capture time. When its
	// proportions disagree with the image, the image was changed afterwards and the
	// thumbnail still shows what the camera saw. That is a fact about the file, not a
	// claim inside it.
	h, dir := harness(t)
	path := writeImage(t, dir, "edited.jpg", jpegWith(thumbnailRecord(160, 160), 4000, 3000))
	runFile(t, h, path)

	var found bool
	for _, f := range h.Out.Findings {
		if f.Kind != "exif-thumbnail-mismatch" {
			continue
		}
		found = true
		if f.Observation.Attrs["consistent_with_image"] != false {
			t.Error("the mismatch was recorded as consistent")
		}
		matched, _ := f.Observation.Attrs["mismatched"].([]string)
		if len(matched) == 0 || matched[0] != "aspect_ratio" {
			t.Errorf("mismatched = %v", matched)
		}
		if note, _ := f.Observation.Attrs["note"].(string); !strings.Contains(note, "changed after capture") {
			t.Errorf("note = %q", note)
		}
		if f.Severity == sdk.SevInfo {
			t.Error("an edit signal is rated as routine")
		}
	}
	if !found {
		t.Fatal("a mismatched thumbnail was not raised")
	}
}

func TestFileWithNoMetadataIsAFinding(t *testing.T) {
	// "No metadata found" says nothing about whether metadata was removed, and a
	// stripped file and one that never had any look identical without that said.
	h, dir := harness(t)
	path := writeImage(t, dir, "clean.png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"))

	runFile(t, h, path)

	var attrs map[string]any
	for _, f := range h.Out.Findings {
		if f.Kind == "exif-no-metadata" {
			attrs = f.Observation.Attrs
		}
	}
	if attrs == nil {
		t.Fatal("a file with no metadata produced no finding")
	}
	if note, _ := attrs["note"].(string); !strings.Contains(note, "whether metadata was removed") {
		t.Errorf("note = %q", note)
	}
}

func TestPathOutsideTheRootsIsRefusedNotObeyed(t *testing.T) {
	// A task value can come from a collector reading attacker-influenced data. An
	// unbounded path turns a metadata reader into an arbitrary file read.
	root := t.TempDir()
	h := sdktest.NewHarness(t, New(WithRoots(root)))
	outside := writeImage(t, t.TempDir(), "elsewhere.jpg", jpegWith(fullRecord(), 4000, 3000))

	runFile(t, h, outside)

	if len(h.Out.Findings) != 0 {
		t.Errorf("a file outside the permitted roots was read: %d findings", len(h.Out.Findings))
	}
	found := false
	for _, w := range h.Out.Warnings {
		if strings.Contains(w, "path refused") {
			found = true
		}
	}
	if !found {
		t.Errorf("the refusal was not reported; warnings: %v", h.Out.Warnings)
	}
}

func TestPrefixIsNotAPathBoundary(t *testing.T) {
	// Comparing with a string prefix would treat /work-evil as inside /work.
	root := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(t.TempDir(), "work-evil")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	path := writeImage(t, sibling, "sneaky.jpg", jpegWith(fullRecord(), 4000, 3000))

	m := New(WithRoots(root))
	if m.allowed(path) {
		t.Errorf("%s was treated as inside %s; a shared string prefix is not containment",
			path, root)
	}
	if !m.allowed(writeImage(t, root, "fine.jpg", []byte("x"))) {
		t.Errorf("a file directly in the root was refused")
	}
}

func TestSymlinkOutOfTheRootIsRefused(t *testing.T) {
	// A symlink can point anywhere, so it is resolved before the check. Checking the
	// link itself would let a link inside the workspace name a target outside it.
	root := t.TempDir()
	outside := writeImage(t, t.TempDir(), "secret.jpg", jpegWith(fullRecord(), 4000, 3000))
	link := filepath.Join(root, "innocent.jpg")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	m := New(WithRoots(root))
	if m.allowed(link) {
		t.Error("a symlink pointing outside the root was accepted")
	}
}

func TestOversizeFileIsRefusedNotTruncated(t *testing.T) {
	// A truncated file's metadata may be intact or cut mid-record, and the two look the
	// same from here.
	h, dir := harness(t, WithMaxBytes(64))
	path := writeImage(t, dir, "big.jpg", jpegWith(fullRecord(), 4000, 3000))

	if err := h.RunTaskExpectingError(sdk.Task{
		Target: sdk.NewEntity(sdk.TypeFile, "aa"),
		Params: map[string]string{sdk.ParamFilePath: path},
	}); err == nil {
		t.Fatal("a file past the size limit must be refused")
	} else if !strings.Contains(err.Error(), "refusing to parse a partial image") {
		t.Errorf("error should name the refusal: %v", err)
	}
}

func TestTruncatedBlockIsRefusedNotGuessed(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "cut.jpg", jpegWith(truncatedRecord(), 4000, 3000))

	// A block cut mid-directory yields no fields. That is the correct outcome: the
	// alternative is emitting the fields that happened to land before the cut.
	runFile(t, h, path)
	for _, f := range h.Out.Findings {
		if f.Kind == "exif-device" {
			t.Error("a truncated block produced a device record")
		}
	}
}

func TestAbsurdDirectoryCountIsRefused(t *testing.T) {
	// A count that cannot fit is a corrupt or hostile file. Trusting it would allocate
	// for entries the block does not contain.
	h, dir := harness(t)
	path := writeImage(t, dir, "huge.jpg", jpegWith(hugeCountRecord(), 4000, 3000))

	runFile(t, h, path)
	for _, f := range h.Out.Findings {
		if strings.HasPrefix(f.Kind, "exif-") && f.Kind != "exif-no-metadata" {
			t.Errorf("an impossible directory produced %q", f.Kind)
		}
	}
}

func TestNonRegularFileIsSkipped(t *testing.T) {
	h, dir := harness(t)
	runFile(t, h, dir)
	if len(h.Out.Findings) != 0 {
		t.Error("a directory was treated as an image")
	}
}

func TestNonImageTargetIsSkipped(t *testing.T) {
	h, _ := harness(t)
	h.Run(sdk.NewEntity(sdk.TypeDomain, "example.com"))
	if len(h.Out.Findings) != 0 {
		t.Error("a domain produced metadata findings")
	}
}

func TestObservationsAreGraded(t *testing.T) {
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	h.AssertObservationsGraded()
	h.AssertNoConfidenceSet()

	// Nothing from a device's own claim about itself reaches top reliability.
	for _, f := range h.Out.Findings {
		if f.Observation.Reliability == 'A' {
			t.Errorf("%s graded A; EXIF is a self-report and is trivially editable", f.Kind)
		}
	}
}

func TestMetadataIsRetainedAsEvidence(t *testing.T) {
	// The raw block is the only way to check a parse made from it.
	h, dir := harness(t)
	path := writeImage(t, dir, "frame.jpg", jpegWith(fullRecord(), 4000, 3000))
	runFile(t, h, path)

	if h.Blobs.Count() == 0 {
		t.Fatal("no metadata retained")
	}
	if !strings.Contains(string(h.Blobs.Bytes()), "EOS 5D Mark IV") {
		t.Error("the retained artifact does not look like the EXIF block")
	}
}

func TestInitNeedsNoDependencies(t *testing.T) {
	// The module contacts nothing, so requiring a client it would never use would make
	// it untestable against anything but a live broker.
	m := New()
	if err := m.Init(context.Background(), sdk.Deps{}); err != nil {
		t.Errorf("Init with no dependencies failed: %v", err)
	}
}

func TestUTF16UserComment(t *testing.T) {
	// The encoding designator in UserComment has three defined values and UNICODE means
	// UTF-16, which a byte-wise reader turns into noise.
	d := &document{blocks: []*tiffDoc{{}}}
	d.blocks[0].exif = &ifd{entries: []entry{{
		tag:   tagUserComment,
		bytes: append([]byte("UNICODE\x00"), utf16le("héllo wörld")...),
	}}}
	if got := userComment(d.blocks[0].exif); got != "héllo wörld" {
		t.Errorf("userComment = %q", got)
	}
}

// utf16le encodes a string as little-endian UTF-16 with a terminator.
func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return append(out, 0, 0)
}
