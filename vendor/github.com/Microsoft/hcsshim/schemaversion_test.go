package hcsshim

import "testing"

// Note that the .syso file is required to manifest the test app
func TestDetermineSchemaVersion(t *testing.T) {
	t.Skip("for now")
	m := make(map[string]string)
	if sv := determineSchemaVersion(nil); !sv.IsV10() { // TODO: Toggle this at some point so default is 2.0
		t.Fatalf("expected v2")
	}
	if sv := determineSchemaVersion(m); !sv.IsV10() { // TODO: Toggle this too
		t.Fatalf("expected v2")
	}
	m[HCSOPTION_SCHEMA_VERSION] = SchemaV20().String()
	if sv := determineSchemaVersion(m); !sv.IsV20() {
		t.Fatalf("expected requested v2")
	}
	m[HCSOPTION_SCHEMA_VERSION] = SchemaV10().String()
	if sv := determineSchemaVersion(m); !sv.IsV10() {
		t.Fatalf("expected requested v1")
	}
	m[HCSOPTION_SCHEMA_VERSION] = (&SchemaVersion{}).String()
	if sv := determineSchemaVersion(m); !sv.IsV10() { // Should also log a warning that 0.0 is ignored // TODO: Toggle this too
		t.Fatalf("expected requested v2")
	}
}
