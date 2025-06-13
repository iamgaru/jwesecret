# 🔐 JWE Secret Store (Go)

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
go run jwe_secret_store.go
```

Or via Docker:

```bash
docker build -t jwe-server .
docker run -p 8080:8888 jwe-server
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

---
