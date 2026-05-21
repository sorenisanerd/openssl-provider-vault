# OpenSSL Vault Provider

An OpenSSL 3 provider that lets OpenSSL use keys stored in HashiCorp Vault's
`transit` secrets engine.

The important bit: the private key stays in Vault. OpenSSL loads a `vault:` key
reference, asks this provider to perform the private-key operation, and the
provider calls Vault's transit API to sign/verify.

## Current status

Implemented and exercised:

- OpenSSL 3 provider module: `vault.so`
- STORE loader for Vault transit key URIs
- Key URI format: `vault:<key-name>` or `vault:<key-name>?version=<n>`
- Vault-backed RSA signing and verification with `openssl pkeyutl`
- Vault-backed RSA X.509 certificate and CSR signing with `openssl req`
- Public-key metadata loading from Vault transit

The project also contains key-management registrations for RSA, EC, and
Ed25519, and signature registrations for RSA, ECDSA, and Ed25519. The command
walkthroughs below use RSA because it is the path verified end-to-end with the
OpenSSL CLI, including CSR and self-signed certificate generation.

## Requirements

- OpenSSL 3.x with provider support
- HashiCorp Vault CLI/server for the demo
- Build dependencies for this project: C compiler, autotools/libtool, OpenSSL
  development headers, libcurl, and json-c

On Debian/Ubuntu-like systems the development packages are typically named:

```sh
sudo apt install build-essential autoconf automake libtool pkg-config \
  libssl-dev libcurl4-openssl-dev libjson-c-dev vault
```

## Build

From the repository root:

```sh
autoreconf -fi
./configure --enable-tests
make
```

For an in-tree build, the provider module is produced at:

```text
src/.libs/vault.so
```

To install it into OpenSSL's module directory:

```sh
sudo make install
```

The install target places the provider under:

```text
$(libdir)/ossl-modules/vault.so
```

## Configure OpenSSL to load the provider

Create an OpenSSL config file. For an in-tree build, replace the `module = ...`
line with the absolute path to this checkout's `src/.libs/vault.so`.

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
vault = vault_sect

[default_sect]
activate = 1

[vault_sect]
module = /absolute/path/to/openssl-provider-vault/src/.libs/vault.so
activate = 1
vault_addr = $ENV::VAULT_ADDR
vault_token = $ENV::VAULT_TOKEN
# Optional, for Vault Enterprise namespaces:
# vault_namespace = $ENV::VAULT_NAMESPACE
```

Save it as, for example:

```sh
export OPENSSL_CONF=$PWD/openssl-vault.cnf
```

If the provider is installed in OpenSSL's normal module directory, you can omit
`module = ...` and let OpenSSL find `vault` by name.

## Demo: run OpenSSL commands backed by Vault

Start a local Vault dev server in one terminal:

```sh
vault server -dev -dev-listen-address=127.0.0.1:8200
```

In another terminal, point both Vault and OpenSSL at it. Use the dev server's
root token shown by Vault:

```sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<dev-root-token>
export OPENSSL_CONF=$PWD/openssl-vault.cnf
```

Enable the transit engine and create a Vault-managed RSA key:

```sh
vault secrets enable transit
vault write -f transit/keys/demo-rsa type=rsa-2048
```

Confirm OpenSSL can see the provider and the `vault:` STORE loader:

```sh
openssl list -providers
openssl list -store-loaders | grep vault
```

Now sign data with `openssl pkeyutl`, using `vault:demo-rsa` as the key. The
private key operation is performed by Vault transit; no private key is written
to disk.

```sh
printf 'hello from OpenSSL backed by Vault\n' > message.txt
openssl dgst -sha256 -binary message.txt > message.sha256

openssl pkeyutl \
  -sign \
  -inkey 'vault:demo-rsa' \
  -in message.sha256 \
  -out message.sig \
  -pkeyopt digest:sha256 \
  -pkeyopt rsa_padding_mode:pss
```

Verify the signature through the same Vault-backed key reference:

```sh
openssl pkeyutl \
  -verify \
  -inkey 'vault:demo-rsa' \
  -in message.sha256 \
  -sigfile message.sig \
  -pkeyopt digest:sha256 \
  -pkeyopt rsa_padding_mode:pss
```

Expected output:

```text
Signature Verified Successfully
```

You can pin a specific Vault key version in the URI:

```sh
openssl pkeyutl \
  -sign \
  -inkey 'vault:demo-rsa?version=1' \
  -in message.sha256 \
  -out message-v1.sig \
  -pkeyopt digest:sha256 \
  -pkeyopt rsa_padding_mode:pss
```

### Sign a CSR with a Vault-backed key

The provider implements OpenSSL's streaming `EVP_DigestSign` signature path, so
commands that sign ASN.1 structures can use a `vault:` key directly. For RSA
digest-sign operations, the provider defaults to PKCS#1 v1.5 padding when the
caller does not set a padding mode; this matches the `sha256WithRSAEncryption`
algorithm identifier OpenSSL writes for ordinary RSA CSRs and certificates.

Create a CSR whose subject public key and signature both come from the Vault
transit key:

```sh
openssl req \
  -new \
  -key 'vault:demo-rsa' \
  -subj '/CN=vault-backed.example' \
  -sha256 \
  -out vault-backed.csr
```

Inspect and verify the CSR signature:

```sh
openssl req -in vault-backed.csr -noout -text
openssl req -in vault-backed.csr -noout -verify
```

Expected verification output:

```text
Certificate request self-signature verify OK
```

### Create a self-signed certificate with a Vault-backed key

You can also create a self-signed X.509 certificate without exporting the
private key from Vault:

```sh
openssl req \
  -new \
  -x509 \
  -key 'vault:demo-rsa' \
  -subj '/CN=vault-backed.example' \
  -sha256 \
  -days 30 \
  -out vault-backed.crt
```

Inspect and verify the certificate with the public key embedded in the
certificate:

```sh
openssl x509 -in vault-backed.crt -noout -text
openssl verify -CAfile vault-backed.crt vault-backed.crt
```

Expected verification output:

```text
vault-backed.crt: OK
```

## Notes and limitations

- Use `openssl pkeyutl` without `-rawin` for the verified RSA path. Hash the
  input first, pass the digest file with `-in`, and set `-pkeyopt digest:sha256`.
- `openssl req` CSR and self-signed certificate generation is verified for
  Vault-managed RSA keys. Those code paths use `EVP_DigestSign` and stream the
  certificate/CSR bytes through OpenSSL's local digest implementation before the
  digest is sent to Vault transit for the private-key signature operation.
- RSA `EVP_DigestSign` defaults to PKCS#1 v1.5 padding when no padding mode is
  provided so OpenSSL can encode the standard `sha*WithRSAEncryption` algorithm
  identifier in X.509 and PKCS#10 structures. Raw `pkeyutl` signing keeps the
  existing PSS default unless you set `-pkeyopt rsa_padding_mode:pkcs1` or
  another supported padding mode.
- The provider currently gets `vault_addr`, `vault_token`, and optional
  `vault_namespace` from OpenSSL provider configuration.
- Do not put production Vault tokens directly in a checked-in OpenSSL config.
  Use environment expansion (`$ENV::VAULT_TOKEN`) as shown above or another
  local secret-management mechanism.
- Vault dev mode is only for local testing. Do not use dev mode in production.

### Debugging

Set `VAULT_PROVIDER_DEBUG=1` to print each HTTP request and response to stderr:

```sh
export VAULT_PROVIDER_DEBUG=1
openssl pkeyutl -sign -inkey 'vault:demo-rsa' ...
```

This logs the HTTP method and URL, the request body if present, and the response
status code and body — useful when diagnosing connectivity or permission issues
with Vault.

## Test

Run the unit tests:

```sh
make check
```

For Vault-backed integration coverage, run a local Vault server, export
`VAULT_ADDR` and `VAULT_TOKEN`, enable transit, and then run:

```sh
make check
make distcheck
```
