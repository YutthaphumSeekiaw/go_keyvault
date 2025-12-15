package main

import (
	"fmt"

	"github.com/go-jose/go-jose/v3"
)

func main() {
	// Create a dummy JWE
	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &jose.JSONWebKey{Key: "dummy"}}, nil)
	// This will fail because key is invalid, but I just want to check the struct or serialization if I could create one.
	// Better to use a real key or just check docs.

	// Let's just check if we can access fields of JSONWebEncryption
	jwe := jose.JSONWebEncryption{}
	// Check for fields corresponding to Flattened JWE
	fmt.Println(jwe.Header)
	fmt.Println(jwe.IV)
	fmt.Println(jwe.Ciphertext)
	fmt.Println(jwe.Tag)
	// fmt.Println(jwe.EncryptedKey) // EncryptedKey is usually in Recipients for General, but maybe top level for Flattened?
	_ = jwe
}
