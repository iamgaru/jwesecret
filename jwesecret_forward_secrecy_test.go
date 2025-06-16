package main

import (
	"reflect"
	"testing"

	"gopkg.in/square/go-jose.v2"
)

func TestECForwardSecrecy(t *testing.T) {
	t.Log("🔐 Starting EC Forward Secrecy Test...")

	err := loadOrGenerateKeysWithType(KeyTypeEC)
	if err != nil {
		t.Fatalf("❌ Failed to load EC keys: %v", err)
	}
	t.Log("✅ EC private key loaded successfully.")

	plaintext := "ForwardSecrecyTest"

	jwe1, err := encryptSecretWithType(plaintext, KeyTypeEC)
	if err != nil {
		t.Fatalf("❌ First encryption failed: %v", err)
	}
	t.Logf("🔑 JWE 1: %s", jwe1)

	jwe2, err := encryptSecretWithType(plaintext, KeyTypeEC)
	if err != nil {
		t.Fatalf("❌ Second encryption failed: %v", err)
	}
	t.Logf("🔑 JWE 2: %s", jwe2)

	if jwe1 == jwe2 {
		t.Errorf("❌ Expected different ciphertexts due to forward secrecy, got identical")
	} else {
		t.Log("✅ Ciphertexts are different as expected.")
	}

	obj1, err := jose.ParseEncrypted(jwe1)
	if err != nil {
		t.Fatalf("❌ Parse failed for JWE 1: %v", err)
	}
	obj2, err := jose.ParseEncrypted(jwe2)
	if err != nil {
		t.Fatalf("❌ Parse failed for JWE 2: %v", err)
	}

	epk1 := obj1.Header.ExtraHeaders[jose.HeaderKey("epk")]
	epk2 := obj2.Header.ExtraHeaders[jose.HeaderKey("epk")]

	t.Logf("📎 Ephemeral Public Key 1: %+v", epk1)
	t.Logf("📎 Ephemeral Public Key 2: %+v", epk2)

	if epk1 == nil || epk2 == nil {
		t.Fatal("❌ Missing 'epk' in one or both JWE headers.")
	}

	if reflect.DeepEqual(epk1, epk2) {
		t.Errorf("❌ Ephemeral public keys should differ but are equal.")
	} else {
		t.Log("✅ Ephemeral public keys are different — forward secrecy is working.")
	}
}

