# TLS Security Toolkit

Automated **TLS/SSL security auditing toolkit** built around `openssl s_client`, together with a
**4-tier hybrid certificate chain** that combines classical and post-quantum cryptography
(RSA, ECDSA, EdDSA, Dilithium5).

> MSc Cybersecurity project — Harokopio University of Athens (HUA), Dept. of Informatics & Telematics.

---

## ✨ Features

- **Protocol auditing** — confirms that only **TLS 1.2 / TLS 1.3** are allowed and that legacy
  protocols (SSLv3, TLS 1.0, TLS 1.1) are rejected.
- **Weak cipher detection** — tests a list of deprecated algorithms (RC4, DES, 3DES, NULL, EXPORT,
  MD5, SHA-1) using the `@SECLEVEL=0` bypass technique.
- **Certificate validation** — checks chain validity, **hostname / domain name** (`-verify_hostname`)
  and **validity dates** (`-dates`, `-checkend`).
- **Hybrid PQC certificate chain** — EdDSA (root) → ECDSA (intermediate 1) → Dilithium5
  (intermediate 2) → RSA (leaf), simulating real-world quantum-migration paths.
- **Vulnerable Nginx lab (bonus)** — a Docker-based Nginx server intentionally misconfigured with
  weak protocols/ciphers for local testing.
- **Comparative assessment** — `testssl.sh` vs Qualys SSL Labs analysis.

---

## 📂 Repository structure

```
.
├── tls-checker.sh            # Main TLS auditing tool (POSIX sh)
├── v3_ca.ext                 # X.509v3 extensions for intermediate CAs
├── v3_leaf.ext               # X.509v3 extensions for the leaf cert (incl. SAN)
├── generate_report.py        # Generates the final .docx report (python-docx)
├── *_cert.pem                # Public certificates (safe to publish)
├── *.csr                     # Certificate signing requests
├── nginx-bonus/
│   ├── nginx.conf            # Intentionally vulnerable Nginx config
│   └── docker-compose.yml    # Orchestration for the vulnerable lab
└── Cybersecurity_Project3_Final.docx
```

> ⚠️ **Private keys are intentionally NOT included** in this repository (see `.gitignore`).
> They can be regenerated locally with the OpenSSL commands below.

---

## 🚀 Usage

### 1. Run the TLS checker

```bash
chmod +x tls-checker.sh
./tls-checker.sh <hostname> [port]

# Examples
./tls-checker.sh badssl.com
./tls-checker.sh expired.badssl.com
./tls-checker.sh localhost 8443
```

### 2. Regenerate keys & the hybrid certificate chain

Requires an OpenSSL build with the **Open Quantum Safe (OQS)** provider
(e.g. the `openquantumsafe/openssl3` Docker image) for the Dilithium5 algorithm.

```bash
# --- Self-signed certificates ---
openssl genrsa -out rsa_private.key 15360
openssl req -x509 -new -key rsa_private.key -days 365 -out rsa_cert.pem \
  -subj "/C=GR/ST=Attica/L=Kallithea/O=HUA/OU=CyberSecurity/CN=RSA 256-bit Level"

openssl ecparam -name secp521r1 -genkey -noout -out ecdsa_private.key
openssl req -x509 -new -key ecdsa_private.key -days 365 -out ecdsa_cert.pem -sha512 \
  -subj "/C=GR/ST=Attica/L=Kallithea/O=HUA/OU=CyberSecurity/CN=ECDSA P-521"

openssl genpkey -algorithm ED448 -out eddsa_private.key
openssl req -x509 -new -key eddsa_private.key -days 365 -out eddsa_cert.pem \
  -subj "/C=GR/ST=Attica/L=Kallithea/O=HUA/OU=CyberSecurity/CN=EdDSA Ed448"

openssl genpkey -algorithm dilithium5 -out pqc_private.key
openssl req -x509 -new -key pqc_private.key -days 365 -out pqc_cert.pem \
  -subj "/C=GR/ST=Attica/L=Kallithea/O=HUA/OU=CyberSecurity/CN=PQC Dilithium5"
```

```bash
# --- Hybrid chain: EdDSA(root) -> ECDSA -> Dilithium5 -> RSA(leaf) ---
openssl req -new -key ecdsa_private.key -out int1_ecdsa.csr \
  -subj "/C=GR/ST=Attica/O=HUA/CN=HUA Intermediate ECDSA CA"
openssl x509 -req -in int1_ecdsa.csr -CA eddsa_cert.pem -CAkey eddsa_private.key \
  -CAcreateserial -out int1_ecdsa_cert.pem -days 365 -extfile v3_ca.ext

openssl req -new -key pqc_private.key -out int2_pqc.csr \
  -subj "/C=GR/ST=Attica/O=HUA/CN=HUA Intermediate Post-Quantum CA"
openssl x509 -req -in int2_pqc.csr -CA int1_ecdsa_cert.pem -CAkey ecdsa_private.key \
  -CAcreateserial -out int2_pqc_cert.pem -days 365 -extfile v3_ca.ext

openssl req -new -key rsa_private.key -out leaf_rsa.csr \
  -subj "/C=GR/ST=Attica/O=HUA/CN=localhost"
openssl x509 -req -in leaf_rsa.csr -CA int2_pqc_cert.pem -CAkey pqc_private.key \
  -CAcreateserial -out leaf_rsa_cert.pem -days 365 -extfile v3_leaf.ext

# --- Verify the chain ---
openssl verify -CAfile eddsa_cert.pem \
  -untrusted int1_ecdsa_cert.pem -untrusted int2_pqc_cert.pem \
  leaf_rsa_cert.pem
```

### 3. Bonus: launch the vulnerable Nginx lab

```bash
cd nginx-bonus
docker compose up -d
./../tls-checker.sh localhost 8443
```

### 4. Comparative assessment (testssl.sh)

```bash
docker run --rm -ti drwetter/testssl.sh <hostname>
```

---

## 🔐 Algorithm choices & security levels

| Algorithm   | Key / Curve      | Security level | Role in chain      |
|-------------|------------------|----------------|--------------------|
| RSA         | 15360-bit        | ~256-bit       | Leaf               |
| ECDSA       | P-521 (secp521r1)| ~256-bit       | Intermediate CA 1  |
| EdDSA       | Ed448            | ~224-bit*      | Root CA            |
| Dilithium5  | NIST Level 5     | ~256-bit (PQC) | Intermediate CA 2  |

\* Ed448 is the strongest standardized EdDSA variant (RFC 8032); the ≥256-bit requirement is
fully met by RSA-15360, ECDSA P-521 and Dilithium5.

---

## ⚠️ Disclaimer

This project is intended **strictly for educational purposes**. The vulnerable Nginx configuration
and weak-cipher tests must never be used in production environments. All certificates here are
self-signed for lab use only.

---

## 📄 License

Released under the MIT License — free to use for educational purposes.
