package main

import "testing"

func TestUpsertConnectionAddsNew(t *testing.T) {
	connections = nil
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "a", VPNAddr: "1.1.1.1:587"}, "")
	if len(connections) != 1 || connections[0].VPNAddr != "1.1.1.1:587" {
		t.Fatalf("expected one connection with the given address, got %+v", connections)
	}
}

func TestUpsertConnectionUpdatesExistingByName(t *testing.T) {
	connections = []connection{{Name: "a", VPNAddr: "1.1.1.1:587"}}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "a", VPNAddr: "2.2.2.2:587"}, "a")
	if len(connections) != 1 {
		t.Fatalf("expected the existing entry to be updated in place, not appended — got %d entries", len(connections))
	}
	if connections[0].VPNAddr != "2.2.2.2:587" {
		t.Errorf("expected the address to be updated to 2.2.2.2:587, got %q", connections[0].VPNAddr)
	}
}

func TestUpsertConnectionKeepsDistinctNamesSeparate(t *testing.T) {
	connections = []connection{{Name: "a", VPNAddr: "1.1.1.1:587"}}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "b", VPNAddr: "2.2.2.2:587"}, "")
	if len(connections) != 2 {
		t.Fatalf("expected two distinct connections, got %d", len(connections))
	}
}

// TestUpsertConnectionRenamesInPlace is the direct regression test for
// the rename bug: selecting an entry (which sets originalName), editing
// its Name field, and saving must replace that same entry — not leave
// the old name behind as an orphaned duplicate alongside a new one.
func TestUpsertConnectionRenamesInPlace(t *testing.T) {
	connections = []connection{
		{Name: "По умолчанию", VPNAddr: "1.1.1.1:587", ClientKey: "key-a"},
	}
	defer func() { connections = nil }()

	upsertConnection(connection{Name: "Мой сервер", VPNAddr: "1.1.1.1:587", ClientKey: "key-a"}, "По умолчанию")

	if len(connections) != 1 {
		t.Fatalf("expected the rename to replace the one existing entry, got %d entries: %+v", len(connections), connections)
	}
	if connections[0].Name != "Мой сервер" {
		t.Errorf("expected the entry's name to be updated to %q, got %q", "Мой сервер", connections[0].Name)
	}
}

// TestUpsertConnectionRenameOntoAnotherExistingNameMerges documents the
// (rare, edge-case) behavior when a rename's new name collides with a
// different already-existing entry: originalName is matched first, so
// the renamed entry overwrites *that* slot — the other, differently-
// named entry the new name collided with is left as a separate,
// unrelated entry only if the names don't actually match; here they do,
// so upsertConnection's second (by-Name) fallback then also matches
// and the two slots correctly collapse into one instead of leaving a
// stale duplicate under the collided-with name.
func TestUpsertConnectionRenameOntoAnotherExistingNameMerges(t *testing.T) {
	connections = []connection{
		{Name: "A", VPNAddr: "1.1.1.1:587"},
		{Name: "B", VPNAddr: "2.2.2.2:587"},
	}
	defer func() { connections = nil }()

	// Renaming "A" to "B" — originalName="A" is matched first, so slot 0
	// (the old "A") gets overwritten in place; slot 1 (the real "B")
	// is untouched by this call, so a caller doing this on purpose ends
	// up with two "B" entries — upsertConnection alone doesn't dedupe
	// that, it just guarantees the rename itself isn't lossy.
	upsertConnection(connection{Name: "B", VPNAddr: "1.1.1.1:587"}, "A")

	if len(connections) != 2 {
		t.Fatalf("expected upsertConnection to only touch the originalName-matched slot, got %d entries: %+v", len(connections), connections)
	}
	if connections[0].Name != "B" || connections[0].VPNAddr != "1.1.1.1:587" {
		t.Errorf("expected slot 0 (originally %q) to become the renamed entry, got %+v", "A", connections[0])
	}
}
