# 🔐 jwesecret – Encrypted Secret Store with JWE + JWT

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

# 🔐 Encryption Process Diagrams (ASCII Overview)

## JWE Encryption with Asymmetric Keys

```
[User Secret]
     |
     v
[Encrypt with Public Key (RSA)]
     |
     v
[AES-GCM Encrypted Payload (JWE)]
     |
     v
[Store or Transmit Securely]
     |
     v
[Recipient Decrypts with Private Key (RSA)]
     |
     v
[Original Secret Recovered]
```

## JWT-Wrapped JWE (with Signing)

```
[User Secret]
     |
     v
[Encrypt with RSA Public Key → JWE]
     |
     v
[Wrap JWE into JWT Claim (e.g., "data")]
     |
     v
[Sign JWT with RSA Private Key]
     |
     v
[JWT Token Sent / Stored]
     |
     v
[Recipient Verifies JWT Signature (Public Key)]
     |
     v
[Extract "data" claim → Encrypted Payload]
     |
     v
[Decrypt JWE using RSA Private Key]
     |
     v
[Recover Original Secret]
```

## HTTP vs CLI Flow

```
                    +-----------------+
                    |  jwesecret App  |
                    +--------+--------+
                             |
               +-------------+-------------+
               |                           |
        [CLI Mode]                  [HTTP Server Mode]
               |                           |
      +--------v---------+         +-------v--------+
      |  Flags:          |         |  Endpoints:    |
      |  --mode encrypt  |         |  /encrypt      |
      |  --input SECRET  |         |  /decrypt      |
      |  [--jwt]         |         |  ?jwt=true     |
      +--------+---------+         +-------+--------+
               |                           |
     +---------v----------+     +----------v---------+
     |  Output to stdout  |     |  Response to client|
     +--------------------+     +--------------------+
```

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
