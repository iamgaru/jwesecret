package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

type KeyType string

const (
	KeyTypeEC  KeyType = "ec"
	KeyTypeRSA KeyType = "rsa"
)

var rsaPriv *rsa.PrivateKey
var ecPriv *ecdsa.PrivateKey

func getKeyType() KeyType {
	if val := os.Getenv("JWE_KEY_TYPE"); val == string(KeyTypeRSA) {
		return KeyTypeRSA
	}
	return KeyTypeEC
}

func loadOrGenerateKeysWithType(kt KeyType) error {
	switch kt {
	case KeyTypeRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		rsaPriv = key
		return nil
	case KeyTypeEC:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		ecPriv = key
		return nil
	default:
		return errors.New("unsupported key type")
	}
}

func encryptSecretWithType(secret string, kt KeyType) (string, error) {
	var pub interface{}
	var alg jose.KeyAlgorithm
	switch kt {
	case KeyTypeRSA:
		pub = rsaPriv.Public()
		alg = jose.RSA_OAEP_256
	case KeyTypeEC:
		pub = ecPriv.Public()
		alg = jose.ECDH_ES_A256KW
	default:
		return "", errors.New("invalid key type")
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: alg, Key: pub},
		(&jose.EncrypterOptions{}).WithType("JWE"),
	)
	if err != nil {
		return "", err
	}
	obj, err := encrypter.Encrypt([]byte(secret))
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func decryptSecretWithType(jwe string, kt KeyType) (string, error) {
	obj, err := jose.ParseEncrypted(jwe)
	if err != nil {
		return "", err
	}
	var plaintext []byte
	switch kt {
	case KeyTypeRSA:
		plaintext, err = obj.Decrypt(rsaPriv)
	case KeyTypeEC:
		plaintext, err = obj.Decrypt(ecPriv)
	default:
		return "", errors.New("invalid key type")
	}
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func wrapInJWTWithType(payload string, kt KeyType) (string, error) {
	claims := jwt.MapClaims{
		"data": payload,
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	}
	var token *jwt.Token
	switch kt {
	case KeyTypeRSA:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		return token.SignedString(rsaPriv)
	case KeyTypeEC:
		token = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		return token.SignedString(ecPriv)
	default:
		return "", errors.New("unsupported key type")
	}
}

func unwrapFromJWTWithType(tokenStr string, kt KeyType) (string, error) {
	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		switch kt {
		case KeyTypeRSA:
			return &rsaPriv.PublicKey, nil
		case KeyTypeEC:
			return &ecPriv.PublicKey, nil
		default:
			return nil, errors.New("unsupported key type")
		}
	})
	if err != nil {
		return "", err
	}
	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		if data, ok := claims["data"].(string); ok {
			return data, nil
		}
		return "", errors.New("no data claim found")
	}
	return "", errors.New("invalid jwt claims")
}

func main() {
	mode := flag.String("mode", "server", "Mode to run: server | encrypt | decrypt")
	input := flag.String("input", "", "Input string to encrypt or decrypt")
	jwtWrap := flag.Bool("jwt", false, "Whether to wrap/unwrap result in JWT")
	flag.Parse()

	keyType := getKeyType()
	if err := loadOrGenerateKeysWithType(keyType); err != nil {
		log.Fatalf("Key init failed: %v", err)
	}

	switch *mode {
	case "encrypt":
		if *input == "" {
			log.Fatal("--input is required for encrypt mode")
		}
		out, err := encryptSecretWithType(*input, keyType)
		if err != nil {
			log.Fatalf("encrypt failed: %v", err)
		}
		if *jwtWrap {
			out, err = wrapInJWTWithType(out, keyType)
			if err != nil {
				log.Fatalf("JWT wrap failed: %v", err)
			}
		}
		fmt.Println(out)

	case "decrypt":
		if *input == "" {
			log.Fatal("--input is required for decrypt mode")
		}
		data := *input
		if *jwtWrap {
			var err error
			data, err = unwrapFromJWTWithType(data, keyType)
			if err != nil {
				log.Fatalf("JWT unwrap failed: %v", err)
			}
		}
		out, err := decryptSecretWithType(data, keyType)
		if err != nil {
			log.Fatalf("decrypt failed: %v", err)
		}
		fmt.Println(out)

	case "server":
		http.HandleFunc("/encrypt", func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusBadRequest)
				return
			}
			enc, err := encryptSecretWithType(string(body), keyType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if r.URL.Query().Get("jwt") == "true" {
				enc, err = wrapInJWTWithType(enc, keyType)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			w.Write([]byte(enc))
		})

		http.HandleFunc("/decrypt", func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusBadRequest)
				return
			}
			data := string(body)
			if r.URL.Query().Get("jwt") == "true" {
				data, err = unwrapFromJWTWithType(data, keyType)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			dec, err := decryptSecretWithType(data, keyType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write([]byte(dec))
		})

		fmt.Println("Server running at http://localhost:8888")
		log.Fatal(http.ListenAndServe(":8888", nil))

	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}
