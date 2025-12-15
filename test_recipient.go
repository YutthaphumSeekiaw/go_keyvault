package main

import (
	"fmt"

	"github.com/go-jose/go-jose/v3"
)

func main() {
	r := jose.Recipient{
		Algorithm: jose.RSA_OAEP,
		KeyID:     "kid",
		//EncryptedKey: []byte{},
		Key: []byte{},
	}
	fmt.Println(r)
}
