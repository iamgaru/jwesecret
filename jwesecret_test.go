package main

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if err := loadOrGenerateKeys(); err != nil {
		panic("key init failed: " + err.Error())
	}
	os.Exit(m.Run())
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	err := loadOrGenerateKeys()
	if err != nil {
		t.Fatalf("failed to init keys: %v", err)
	}

	original := "test-secret"
	jwe, err := encryptSecret(original)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptSecret(jwe)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if decrypted != original {
		t.Errorf("expected %q, got %q", original, decrypted)
	}
}

func TestJWTWrapUnwrap(t *testing.T) {
	err := loadOrGenerateKeys()
	if err != nil {
		t.Fatalf("failed to init keys: %v", err)
	}

	data := "some-encrypted-data"
	jwtToken, err := wrapInJWT(data)
	if err != nil {
		t.Fatalf("JWT wrap failed: %v", err)
	}

	extracted, err := unwrapFromJWT(jwtToken)
	if err != nil {
		t.Fatalf("JWT unwrap failed: %v", err)
	}

	if extracted != data {
		t.Errorf("expected %q, got %q", data, extracted)
	}
}

func TestEncryptThenJWTWrap(t *testing.T) {
	err := loadOrGenerateKeys()
	if err != nil {
		t.Fatalf("failed to init keys: %v", err)
	}

	secret := "jwt-secret"
	jwe, err := encryptSecret(secret)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	jwtToken, err := wrapInJWT(jwe)
	if err != nil {
		t.Fatalf("wrapInJWT failed: %v", err)
	}

	extractedJWE, err := unwrapFromJWT(jwtToken)
	if err != nil {
		t.Fatalf("unwrapFromJWT failed: %v", err)
	}

	decrypted, err := decryptSecret(extractedJWE)
	if err != nil {
		t.Fatalf("decryptSecret failed: %v", err)
	}

	if decrypted != secret {
		t.Errorf("expected %q, got %q", secret, decrypted)
	}
}
