// Command genkey makes a key pair for one client: the public key goes to
// the server's authorized_keys.json, the private one to client-config.json.
package main

import (
	"flag"
	"fmt"
	"os"

	"tcp-dormtun/internal/auth"
)

func main() {
	name := flag.String("name", "friend", "label for this identity, just for your own authorized_keys.json bookkeeping")
	from := flag.String("pub", "", "print the authorized_keys.json entry for an existing client_key instead of making a new pair")
	flag.Parse()

	if *from != "" {
		seed, err := auth.DecodeKey(*from)
		if err == nil {
			var pub []byte
			pub, err = auth.PublicKeyFromSeed(seed)
			if err == nil {
				fmt.Printf("  { \"name\": %q, \"public_key\": %q }\n", *name, auth.EncodeKey(pub))
				return
			}
		}
		fmt.Println("bad client_key:", err)
		os.Exit(1)
	}

	pub, seed, err := auth.GenerateKeypair()
	if err != nil {
		fmt.Println("generate keypair:", err)
		return
	}

	fmt.Println("Add this entry to the SERVER's authorized_keys.json (see authorized_keys.example.json):")
	fmt.Println()
	fmt.Printf("  { \"name\": %q, \"public_key\": %q }\n", *name, auth.EncodeKey(pub))
	fmt.Println()
	fmt.Println("(the line above is not secret)")
	fmt.Println()
	fmt.Println("Give this to that SAME person for their client-config.json (client_key field):")
	fmt.Println()
	fmt.Printf("  \"client_key\": %q\n", auth.EncodeKey(seed))
	fmt.Println()
	fmt.Println("This is the private key, don't share it with anyone else.")
}
