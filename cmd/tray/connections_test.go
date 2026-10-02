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
		t.Fatalf("expected 1 entry, got %d", len(connections))
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

// Renaming an entry should not leave the old one in the list.
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

// Renaming A to an existing name B only changes A's slot.
func TestUpsertConnectionRenameOntoAnotherExistingNameMerges(t *testing.T) {
	connections = []connection{
		{Name: "A", VPNAddr: "1.1.1.1:587"},
		{Name: "B", VPNAddr: "2.2.2.2:587"},
	}
	defer func() { connections = nil }()

	// we end up with two "B" entries, that's ok here
	upsertConnection(connection{Name: "B", VPNAddr: "1.1.1.1:587"}, "A")

	if len(connections) != 2 {
		t.Fatalf("expected upsertConnection to only touch the originalName-matched slot, got %d entries: %+v", len(connections), connections)
	}
	if connections[0].Name != "B" || connections[0].VPNAddr != "1.1.1.1:587" {
		t.Errorf("expected slot 0 (originally %q) to become the renamed entry, got %+v", "A", connections[0])
	}
}
