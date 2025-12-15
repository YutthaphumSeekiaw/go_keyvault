package jwx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v3"
)

// CustomJWEHeader represents the header part of the custom JSON format.
type CustomJWEHeader struct {
	Alg string `json:"alg"`
	Cty string `json:"cty,omitempty"`
	Enc string `json:"enc"`
}

// CustomJWE represents the custom JSON format requested by the user.
type CustomJWE struct {
	Header       CustomJWEHeader `json:"header"`
	EncryptedKey string          `json:"encrypted_key"`
	IV           string          `json:"iv"`
	Ciphertext   string          `json:"ciphertext"`
	Tag          string          `json:"tag"`
}

// CompactToCustomJSON converts a JWE Compact string to the Custom JSON format string.
func CompactToCustomJSON(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid JWE compact format: expected 5 parts, got %d", len(parts))
	}

	// Compact parts: Header.EncryptedKey.IV.Ciphertext.Tag
	headerB64 := parts[0]
	encryptedKey := parts[1]
	iv := parts[2]
	ciphertext := parts[3]
	tag := parts[4]

	// Parse Header to get alg/enc/cty
	jweObj, err := jose.ParseEncrypted(compact)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWE: %w", err)
	}

	// In go-jose v3, Header struct might not have ContentEncryption field directly exposed?
	// Let's check if we can get it from ExtraHeaders or if it's named differently.
	// Actually, for JWE, 'enc' is in the protected header.
	// jweObj.Header contains the protected header.

	// If ContentEncryption is not a field, we might need to look at how go-jose stores it.
	// It seems go-jose v3 Header struct has: Algorithm, KeyID, JSONWebKey, ExtraHeaders.
	// 'enc' might be in ExtraHeaders? Or maybe it's not exposed in Header struct but in the JWE object?
	// jweObj.ContentEncryption? No, JWE object has Recipients.

	// Let's try to get it from ExtraHeaders first.
	var enc string
	if val, ok := jweObj.Header.ExtraHeaders["enc"]; ok {
		if s, ok := val.(string); ok {
			enc = s
		}
	}
	// If not in ExtraHeaders, maybe it's a field I missed.
	// But wait, 'enc' is a standard header. go-jose usually handles it.
	// Let's assume for now it's in ExtraHeaders or we can't get it easily without decrypting?
	// No, it's unencrypted header.

	// Alternative: Decode the header part manually since we have the base64 string.
	// headerB64 is available.
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode header: %w", err)
	}

	var rawHeader map[string]interface{}
	if err := json.Unmarshal(headerBytes, &rawHeader); err != nil {
		return "", fmt.Errorf("failed to unmarshal header JSON: %w", err)
	}

	alg, _ := rawHeader["alg"].(string)
	enc, _ = rawHeader["enc"].(string)
	cty, _ := rawHeader["cty"].(string)

	header := CustomJWEHeader{
		Alg: alg,
		Enc: enc,
		Cty: cty,
	}

	customJWE := CustomJWE{
		Header:       header,
		EncryptedKey: encryptedKey,
		IV:           iv,
		Ciphertext:   ciphertext,
		Tag:          tag,
	}

	jsonBytes, err := json.MarshalIndent(customJWE, "", "    ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal custom JWE: %w", err)
	}

	return string(jsonBytes), nil
}

// CustomJSONToCompact converts the Custom JSON format string back to JWE Compact string.
func CustomJSONToCompact(jsonStr string) (string, error) {
	var customJWE CustomJWE
	err := json.Unmarshal([]byte(jsonStr), &customJWE)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal custom JWE: %w", err)
	}

	// Reconstruct Header
	headerMap := map[string]interface{}{
		"alg": customJWE.Header.Alg,
		"enc": customJWE.Header.Enc,
	}
	if customJWE.Header.Cty != "" {
		headerMap["cty"] = customJWE.Header.Cty
	}

	headerJSON, err := json.Marshal(headerMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Compact: Header.EncryptedKey.IV.Ciphertext.Tag
	return fmt.Sprintf("%s.%s.%s.%s.%s",
		headerB64,
		customJWE.EncryptedKey,
		customJWE.IV,
		customJWE.Ciphertext,
		customJWE.Tag,
	), nil
}
