package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cases := []KeyType{KeyTypeEC, KeyTypeRSA}
	for _, kt := range cases {
		t.Run(string(kt), func(t *testing.T) {
			err := loadOrGenerateKeysWithType(kt)
			if err != nil {
				t.Fatalf("failed to init keys: %v", err)
			}

			input := "secret-data"
			jwe, err := encryptSecretWithType(input, kt)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			out, err := decryptSecretWithType(jwe, kt)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if out != input {
				t.Errorf("expected %q, got %q", input, out)
			}
		})
	}
}

func TestJWTWrapUnwrap(t *testing.T) {
	cases := []KeyType{KeyTypeEC, KeyTypeRSA}
	for _, kt := range cases {
		t.Run(string(kt), func(t *testing.T) {
			err := loadOrGenerateKeysWithType(kt)
			if err != nil {
				t.Fatalf("failed to init keys: %v", err)
			}

			input := "wrapped-payload"
			token, err := wrapInJWTWithType(input, kt)
			if err != nil {
				t.Fatalf("JWT wrap failed: %v", err)
			}

			unwrapped, err := unwrapFromJWTWithType(token, kt)
			if err != nil {
				t.Fatalf("JWT unwrap failed: %v", err)
			}

			if unwrapped != input {
				t.Errorf("expected %q, got %q", input, unwrapped)
			}
		})
	}
}

func TestEncryptThenJWTWrap(t *testing.T) {
	cases := []KeyType{KeyTypeEC, KeyTypeRSA}
	for _, kt := range cases {
		t.Run(string(kt), func(t *testing.T) {
			err := loadOrGenerateKeysWithType(kt)
			if err != nil {
				t.Fatalf("failed to init keys: %v", err)
			}

			secret := "jwt-wrapped-encrypted"
			jwe, err := encryptSecretWithType(secret, kt)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			token, err := wrapInJWTWithType(jwe, kt)
			if err != nil {
				t.Fatalf("JWT wrap failed: %v", err)
			}

			jweOut, err := unwrapFromJWTWithType(token, kt)
			if err != nil {
				t.Fatalf("JWT unwrap failed: %v", err)
			}

			decrypted, err := decryptSecretWithType(jweOut, kt)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if decrypted != secret {
				t.Errorf("expected %q, got %q", secret, decrypted)
			}
		})
	}
}
