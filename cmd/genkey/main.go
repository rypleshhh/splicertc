// Command genkey generates one Ed25519 identity for splicertc's
// per-client authentication (internal/auth): a public key that goes in
// the server's authorized_keys.json, and a private key that goes in
// that one client's client-config.json. Run it once per person you want
// to grant access to — including yourself for a personal deployment.
package main

import (
	"flag"
	"fmt"

	"tcp-dormtun/internal/auth"
)

func main() {
	name := flag.String("name", "friend", "label for this identity, just for your own authorized_keys.json bookkeeping")
	flag.Parse()

	pub, seed, err := auth.GenerateKeypair()
	if err != nil {
		fmt.Println("generate keypair:", err)
		return
	}

	fmt.Println("Add this entry to the SERVER's authorized_keys.json (see authorized_keys.example.json):")
	fmt.Println()
	fmt.Printf("  { \"name\": %q, \"public_key\": %q }\n", *name, auth.EncodeKey(pub))
	fmt.Println()
	fmt.Println("Send ONLY the line above to the person this key is for — it's not secret.")
	fmt.Println()
	fmt.Println("Give this to that SAME person for their client-config.json (client_key field):")
	fmt.Println()
	fmt.Printf("  \"client_key\": %q\n", auth.EncodeKey(seed))
	fmt.Println()
	fmt.Println("This second value is a private key — send it over a channel you trust, the same way you'd have shared the old psk. Anyone who has it can connect as this identity.")
}
