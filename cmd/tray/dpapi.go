package main

import (
	"encoding/base64"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Private keys in connections.json are encrypted with DPAPI for the
// current Windows user: a copy of the file (backup, another account, a
// stolen disk) is useless without the user's login. Programs running as
// this same user can still decrypt it, DPAPI doesn't protect from those.

// dpapiEntropy is mixed into the encryption so a generic "decrypt this
// blob" call by some other program doesn't work without knowing it.
var dpapiEntropy = []byte("splicertc client_key")

func protectString(plain string) (string, error) {
	in := blobOf([]byte(plain))
	entropy := blobOf(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(takeBlob(out)), nil
}

func unprotectString(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", err
	}
	in := blobOf(raw)
	entropy := blobOf(dpapiEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", err
	}
	return string(takeBlob(out)), nil
}

func blobOf(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// takeBlob copies a blob DPAPI allocated and frees it.
func takeBlob(b windows.DataBlob) []byte {
	if b.Data == nil {
		return nil
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return append([]byte(nil), unsafe.Slice(b.Data, b.Size)...)
}
