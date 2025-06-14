# 🔐 jwesecret – Encrypted Secret Store with JWE + JWT in Go

**jwesecret** is a lightweight Go server and CLI for storing and retrieving secrets (e.g., WiFi passwords, API keys) using **asymmetric encryption** via [JWE (JSON Web Encryption)](https://datatracker.ietf.org/doc/html/rfc7516). Secrets can optionally be wrapped in a signed **JWT**, allowing for identity-carrying, tamper-proof payloads.

- 💂 Secure: RSA-OAEP + AES-GCM encryption
- 🔏 Optional JWT wrapping (`?jwt=true` or `--jwt`)
- 🧪 Includes unit tests for roundtrip encryption and JWT verification
- 🐳 Dockerized with persistent key support
- 🛠 Dual mode: HTTP server or CLI

## 🚀 Features

- 🔒 RSA-2048 key generation and persistence
- 🔐 JWE encryption (AES-GCM + RSA-OAEP)
- 🧾 Optional JWT wrapping (`?jwt=true`)
- 🌐 HTTP server with `/encrypt` and `/decrypt` endpoints
- 🛠 CLI interface with `--mode encrypt|decrypt`
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

### Encrypt a secret via HTTP

```bash
curl -X POST http://localhost:8888/encrypt -d 'super-secret'
```

With JWT wrapping:

```bash
curl -X POST 'http://localhost:8888/encrypt?jwt=true' -d 'super-secret'
```

### Decrypt a secret via HTTP

```bash
curl -X POST http://localhost:8888/decrypt -d '<JWE>'
```

With JWT:

```bash
curl -X POST http://localhost:8888/decrypt?jwt=true -d '<JWT>'
```

### CLI encryption

```bash
go run jwesecret.go --mode encrypt --input "my secret"
```

With JWT wrapping:

```bash
go run jwesecret.go --mode encrypt --input "my secret" --jwt
```

### CLI decryption

```bash
go run jwesecret.go --mode decrypt --input "<jwe-or-jwt>" --jwt
```

### CLI help

```bash
go run jwesecret.go --help

# Output:
# -mode string
#       Mode: serve | encrypt | decrypt (default "serve")
# -input string
#       Input to encrypt/decrypt
# -jwt
#       Wrap/unwrap input/output as JWT
```

## 📚 Dependencies

- [go-jose](https://github.com/square/go-jose)
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)

## ✍️ Author & Version

| Key         | Value                                      |
|--------------|---------------------------------------------|
| **Author**   | Nick Conolly                               |
| **Version**  | 0.0.1                                       |
| **GitHub**   | [@iamgaru](https://github.com/iamgaru)     |
| **License**  | [MIT](LICENSE)                             |
