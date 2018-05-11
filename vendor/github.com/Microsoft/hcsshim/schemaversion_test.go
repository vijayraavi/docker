package hcsshim

import "testing"

// Note that the .syso file is required to manifest the test app
func TestDetermineSchemaVersion(t *testing.T) {
	//	t.Skip("for now")
	if sv := determineSchemaVersion(nil); !sv.IsV10() { // TODO: Toggle this at some point so default is 2.0
		t.Fatalf("expected v2")
	}
	if sv := determineSchemaVersion(SchemaV20()); !sv.IsV20() {
		t.Fatalf("expected requested v2")
	}
	if sv := determineSchemaVersion(SchemaV10()); !sv.IsV10() {
		t.Fatalf("expected requested v1")
	}
	if sv := determineSchemaVersion(&SchemaVersion{}); !sv.IsV10() { // Should also log a warning that 0.0 is ignored // TODO: Toggle this too
		t.Fatalf("expected requested v2")
	}
}
