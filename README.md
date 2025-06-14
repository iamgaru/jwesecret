# 🔐 jwesecret – Encrypted Secret Store with JWE + JWT in Go

**jwesecret** is a lightweight Go server for storing and retrieving secrets (e.g., WiFi passwords, API keys) using **asymmetric encryption** via [JWE (JSON Web Encryption)](https://datatracker.ietf.org/doc/html/rfc7516). Secrets can optionally be wrapped in a signed **JWT**, allowing for identity-carrying, tamper-proof payloads.

- 💂 Secure: RSA-OAEP + AES-GCM encryption
- 🔏 Optional JWT wrapping (`?jwt=true`) for claim-based token delivery
- 🧪 Includes unit tests for roundtrip encryption and JWT verification
- 🐳 Dockerized with persistent key support

# 🔐 jwesecret (Go)

This is a proof-of-concept Go server that securely stores and retrieves secrets using **JWE** (JSON Web Encryption) and optionally wraps the encrypted payload in a **JWT** for additional integrity and claim-based access control.

## 🚀 Features

- 🔒 RSA-2048 key generation and persistence
- 🔐 JWE encryption (AES-GCM + RSA-OAEP)
- 🧾 Optional JWT wrapping (`?jwt=true`)
- 🌐 HTTP server with `/encrypt` and `/decrypt` endpoints
- 🐳 Docker support

## 🛠 Usage

### Start the server

```bash
go run jwesecret.go
```

Or via Docker:

```bash
docker build -t jwesecret .
docker run -p 8888:8888 jwesecret
```

### Encrypt a secret

```bash
curl -X POST http://localhost:8888/encrypt -d 'super-secret'
```

With JWT wrapping:

```bash
curl -X POST 'http://localhost:8888/encrypt?jwt=true' -d 'super-secret'
```

### Decrypt a secret

```bash
curl -X POST http://localhost:8888/decrypt -d '<JWE>'
```

Or with JWT:

```bash
curl -X POST 'http://localhost:8888/decrypt?jwt=true' -d '<JWT>'
```

## 📚 Dependencies

- [go-jose](https://github.com/square/go-jose)
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)

