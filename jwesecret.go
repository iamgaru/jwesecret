package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jose "gopkg.in/square/go-jose.v2"
)

var rsaPrivKey *rsa.PrivateKey
var rsaPubKey *rsa.PublicKey

const (
	privKeyPath = "private.pem"
	pubKeyPath  = "public.pem"
)

func loadOrGenerateKeys() error {
	if privPEM, err := os.ReadFile(privKeyPath); err == nil {
		block, _ := pem.Decode(privPEM)
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		rsaPrivKey = key
		rsaPubKey = &rsaPrivKey.PublicKey // ✅ Fix: ensure rsaPubKey is set
		return nil
	}

	// Generate new keys
	var err error
	rsaPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	rsaPubKey = &rsaPrivKey.PublicKey

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey)})
	pubASN1, _ := x509.MarshalPKIXPublicKey(rsaPubKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1})

	_ = os.WriteFile(privKeyPath, privPEM, 0600)
	_ = os.WriteFile(pubKeyPath, pubPEM, 0644)
	return nil
}

func encryptSecret(secret string) (string, error) {
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.RSA_OAEP,
		Key:       rsaPubKey,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	obj, err := encrypter.Encrypt([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	return obj.FullSerialize(), nil
}

func decryptSecret(serialized string) (string, error) {
	obj, err := jose.ParseEncrypted(serialized)
	if err != nil {
		return "", fmt.Errorf("failed to parse encrypted string: %w", err)
	}
	decrypted, err := obj.Decrypt(rsaPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(decrypted), nil
}

func wrapJWT(claimKey, value string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		claimKey: value,
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	return tok.SignedString(rsaPrivKey)
}

func unwrapJWT(tokenStr, claimKey string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return rsaPubKey, nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid claims")
	}
	val, ok := claims[claimKey].(string)
	if !ok {
		return "", errors.New("claim not found")
	}
	return val, nil
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	useJWT := r.URL.Query().Get("jwt") == "true"
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		http.Error(w, "missing body", http.StatusBadRequest)
		return
	}
	ciphertext, err := encryptSecret(string(data))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if useJWT {
		ciphertext, err = wrapJWT("enc", ciphertext)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Write([]byte(ciphertext))
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	useJWT := r.URL.Query().Get("jwt") == "true"
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		http.Error(w, "missing body", http.StatusBadRequest)
		return
	}
	payload := string(data)
	if useJWT {
		payload, err = unwrapJWT(payload, "enc")
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
	}
	plaintext, err := decryptSecret(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(plaintext))
}

func main() {
	if err := loadOrGenerateKeys(); err != nil {
		log.Fatalf("failed to init keys: %v", err)
	}

	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	fmt.Println("Server running at http://localhost:8888")
	log.Fatal(http.ListenAndServe(":8888", nil))
}
