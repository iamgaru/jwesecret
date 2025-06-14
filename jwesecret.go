// jwesecret.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
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
		rsaPubKey = &rsaPrivKey.PublicKey
		return nil
	}

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
	recipient := jose.Recipient{
		Algorithm: jose.RSA_OAEP,
		Key:       rsaPubKey,
	}
	opts := jose.EncrypterOptions{}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, &opts)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	serialized := jwe.FullSerialize()
	return serialized, nil
}

func decryptSecret(jweStr string) (string, error) {
	jweObj, err := jose.ParseEncrypted(jweStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse JWE: %w", err)
	}

	decrypted, err := jweObj.Decrypt(rsaPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(decrypted), nil
}

func wrapInJWT(payload string) (string, error) {
	claims := jwt.MapClaims{
		"data": payload,
		"exp":  time.Now().Add(10 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(rsaPrivKey)
}

func unwrapFromJWT(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPubKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to parse JWT: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if data, ok := claims["data"].(string); ok {
			return data, nil
		}
		return "", errors.New("JWT does not contain 'data' field")
	}

	return "", errors.New("invalid JWT or claims")
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	wrap := r.URL.Query().Get("jwt") == "true"
	var resp string
	if wrap {
		resp, err = wrapInJWT(string(body))
	} else {
		resp, err = encryptSecret(string(body))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(resp))
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	wrapped := r.URL.Query().Get("jwt") == "true"
	var resp string
	if wrapped {
		resp, err = unwrapFromJWT(string(body))
	} else {
		resp, err = decryptSecret(string(body))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(resp))
}

func main() {
	mode := flag.String("mode", "server", "Mode: server | encrypt | decrypt")
	input := flag.String("input", "", "Input string to encrypt or decrypt")
	jwtMode := flag.Bool("jwt", false, "Use JWT wrapping/unwrapping")
	flag.Parse()

	if err := loadOrGenerateKeys(); err != nil {
		log.Fatal("key error:", err)
	}

	switch *mode {
	case "encrypt":
		if *input == "" {
			log.Fatal("missing input for encryption")
		}
		ciphertext, err := encryptSecret(*input)
		if err != nil {
			log.Fatal("encryption failed:", err)
		}
		if *jwtMode {
			jwtToken, err := wrapInJWT(ciphertext)
			if err != nil {
				log.Fatal("JWT wrap failed:", err)
			}
			fmt.Println(jwtToken)
			return
		}
		fmt.Println(ciphertext)
		return

	case "decrypt":
		if *input == "" {
			log.Fatal("missing input for decryption")
		}
		data := *input
		if *jwtMode {
			var err error
			data, err = unwrapFromJWT(data)
			if err != nil {
				log.Fatal("JWT unwrap failed:", err)
			}
		}
		plaintext, err := decryptSecret(data)
		if err != nil {
			log.Fatal("decryption failed:", err)
		}
		fmt.Println(plaintext)
		return

	default:
		fmt.Println("Server running at http://localhost:8888")
		http.HandleFunc("/encrypt", encryptHandler)
		http.HandleFunc("/decrypt", decryptHandler)
		log.Fatal(http.ListenAndServe(":8888", nil))
	}
}
