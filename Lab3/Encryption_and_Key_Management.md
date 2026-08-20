# IKB42603 Lab 3: Encryption and Key Management

**Student:** Affiq
**Student ID:** 52215124425  
**Module:** IKB42603  
**Lab:** Encryption and Key Management  

## Objectives

This lab explored how encryption protects information at rest and in transit, and how key-management decisions affect the security of the same information. The practical objectives were to:

- encrypt and recover a sensitive patient record with symmetric and asymmetric cryptography;
- prove authenticity and integrity with a digital signature;
- publish protected content through a TLS-enabled service;
- create and use AWS KMS customer-managed keys, including envelope encryption;
- observe how the KMS key lifecycle prevents use of a key pending deletion; and
- detect changes to important files through SHA-256 integrity monitoring.

## Learning outcomes

After completing the lab, I can select an appropriate encryption approach for a small scenario, distinguish encryption from signing, and explain why private keys and data-encryption keys need stricter handling than public material. I also gained hands-on familiarity with OpenSSL, Docker, curl, the AWS CLI, and basic shell tools used for integrity checking.

## Tools used

| Tool | Purpose in this lab |
| --- | --- |
| Kali Linux terminal | Ran the cryptographic and verification commands. |
| OpenSSL | Performed AES encryption, RSA operations, signing, certificate creation, and hashing. |
| Docker | Hosted the test file in a TLS-enabled Nginx container. |
| curl | Retrieved the protected file over HTTPS. |
| AWS CLI / AWS KMS | Created KMS keys, protected a data key, and exercised lifecycle controls. |
| `sha256sum`, `awk`, shell loop | Created and checked a simple integrity baseline. |

## Task 1 – Symmetric encryption with AES-256-CBC

### Purpose

Protect the confidentiality of a patient record using one shared secret, then demonstrate that the original plaintext can be recovered only with the correct password.

### Commands used

```bash
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc
cat record.enc
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

### Result

OpenSSL produced an unreadable ciphertext file (`record.enc`). After entering the same passphrase for decryption, `diff` returned no differences and printed **MATCH: decryption successful**. This confirms confidentiality in storage and successful recovery of the original record. PBKDF2 and a salt make password-derived keys more resistant to guessing attacks than a direct password-to-key approach.

### Screenshot

![Task 1: AES encryption and successful decryption](Task%201.png)

## Task 2 – RSA encryption and digital signatures

### Purpose

Use a public/private key pair for asymmetric encryption, then use the same key pair in a separate signing workflow to verify integrity and origin.

### Task 2.1 – Generate keys and encrypt/decrypt the record

#### Commands used

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt
diff record.txt record.rsa.txt && echo 'RSA DECRYPTION MATCH'
```

#### Result

A 2048-bit RSA private key and matching public key were generated. The record was encrypted with the public key and successfully decrypted with the private key; the comparison displayed **RSA DECRYPTION MATCH**. The public key can be distributed, whereas `private.pem` must remain secret.

#### Screenshot

![Task 2.1: RSA key generation, encryption, and decryption](Task%202.1.png)

### Task 2.2 – Sign and verify the record

#### Commands used

```bash
cat record.rsa.txt
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

#### Result

The decrypted content was the expected patient record. OpenSSL returned **Verified OK** for the SHA-256 signature. Unlike encryption, the signature does not hide the file; it gives evidence that the data was not changed after it was signed and that the holder of the private key signed it.

#### Screenshot

![Task 2.2: record content and successful signature verification](Task%202.2.png)

## Task 3 – TLS-protected file delivery

### Purpose

Create a short-lived self-signed certificate and use it to serve the sensitive record through HTTPS.

### Task 3.1 – Create the certificate and key

#### Command used

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 7 -nodes -subj '/CN=localhost'
```

#### Result

OpenSSL generated an RSA private key and a self-signed X.509 certificate for `localhost`, valid for seven days. A short validity period is appropriate for a lab certificate and reinforces that certificates should be rotated rather than treated as permanent.

#### Screenshot

![Task 3.1: self-signed TLS certificate generation](Task%203.1.png)

### Task 3.2 – Start the TLS web service

#### Command used

```bash
docker run -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
  -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt \
  nginx
```

#### Result

Docker started a container and returned its container ID. The certificate, private key, and record were mounted into the service to make the test resource available on port 8443.

#### Screenshot

![Task 3.2: TLS container started](Task%203.2.png)

### Task 3.3 – Retrieve the file over HTTPS

#### Command used

```bash
curl -k https://localhost:8443/record.txt
```

#### Result

The request returned `Patient: Ahmad, Diagnosis: confidential`. The `-k` option was necessary only because the lab used a self-signed certificate. In production, clients should validate a certificate issued by a trusted CA and should not bypass certificate verification.

#### Screenshot

![Task 3.3: HTTPS retrieval of the record](Task%203.3.png)

## Task 4 – Create a customer-managed KMS key and encrypt data

### Purpose

Create a KMS master key for tenant A, then ask KMS to encrypt a small plaintext value.

### Commands used

```bash
EP='--endpoint-url=http://localhost:4566'
aws $EP kms create-key --description 'CCSE tenant-A master key'
KEY_A='290731ef-dcec-4380-b5e8-af59493d7ca3'
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text > hello.enc.b64
cat hello.enc.b64
```

### Result

The KMS response showed an enabled, customer-managed symmetric key with `ENCRYPT_DECRYPT` usage. KMS returned a base64 ciphertext blob for `hello`; the plaintext was not exposed in the output. The key ID shown above is the value captured in this lab evidence.

### Screenshot

![Task 4: KMS key creation and ciphertext output](Task%204.png)

## Task 5 – Envelope encryption with KMS

### Purpose

Use KMS to generate a data key, encrypt the record locally with that data key, and retain only the KMS-wrapped key alongside the ciphertext.

### Commands used

```bash
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text > datakey.pair
PLAINTEXT_B64=$(awk '{print $1}' datakey.pair)
CIPHER_B64=$(awk '{print $2}' datakey.pair)
echo "$PLAINTEXT_B64" > datakey.b64
echo "$CIPHER_B64" > datakey.enc.b64
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc \
  -pass file://datakey.bin
rm datakey.bin datakey.b64
ls -l datakey.enc.b64 record.env.enc
```

### Result

KMS generated an AES-256 data key in plaintext and encrypted form. The plaintext key was briefly decoded only to encrypt `record.txt`, then removed with its base64 copy. The remaining artifacts were `record.env.enc` and the KMS-wrapped `datakey.enc.b64`. This is envelope encryption: KMS protects the small data key, while the data key protects the larger file.

### Screenshot

![Task 5: envelope encryption and remaining artifacts](Task%205.png)

## Task 6 – Key lifecycle and deletion protection

### Purpose

Create another customer-managed key, schedule its deletion, and observe that a key pending deletion cannot be disabled or used to decrypt.

### Commands used

```bash
aws $EP kms create-key --description 'CCSE tenant-B master key'
KEY_B='673cabd6-26a3-437e-ada2-42440cc8cc7d'
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7
aws $EP kms disable-key --key-id $KEY_A
base64 -d datakey.enc.b64 > datakey.enc.bin
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc.bin 2>&1
```

### Result

The tenant-B key was created successfully. Key A was then placed in **PendingDeletion** with a seven-day deletion window. Subsequent `DisableKey` and `Decrypt` attempts returned `KMSInvalidStateException`, which is the expected result: a key in this lifecycle state cannot be used. This makes scheduled deletion a high-impact change that should require review, recovery planning, and the ability to cancel deletion during the waiting window.

### Screenshot

![Task 6: scheduled deletion and expected KMS errors](Task%206.png)

## Task 7 – File-integrity monitoring

### Purpose

Create an integrity baseline for selected files and compare it after a change.

### Commands used

```bash
cp record.txt tampered.txt
echo 'x' >> tampered.txt
sha256sum record.txt tampered.txt
PREV=0
for line in 'login ok' 'file read' 'export data'; do
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d ' ' -f1)
  echo "$line | $PREV"
done
```

### Result

Appending a single character to `tampered.txt` produced a different SHA-256 digest from `record.txt`. The small chained-hash example also shows how each event affects the next value. Hashing does not encrypt content, but it gives a compact way to identify unexpected modification when the trusted baseline is protected.

### Screenshot

![Task 7: differing SHA-256 values and chained hashes](Task%207.png)

## Short-Answer Questions

### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.
   Symmetric encryption uses one shared key for encryption and decryption. It is fast and suitable for large files, databases, and backups, but both parties must obtain and protect the same secret key securely. Asymmetric encryption uses a public/private key pair. It is slower, but the public key can be shared openly; it is commonly used for key exchange, digital signatures, certificates, and encrypting small secrets such as data-encryption keys.

### Q2. Why is key management described as the weakest link, not the algorithm?  
   Strong algorithms such as AES and RSA are ineffective if keys are exposed, copied into source code, stored insecurely, shared with too many people, or deleted accidentally. Real security depends on how keys are generated, stored, accessed, rotated, audited, backed up, and retired. An attacker who obtains a valid decryption key does not need to break the encryption algorithm.

### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.  
   Envelope encryption uses a temporary data-encryption key to encrypt the actual file locally. That data key is then encrypted (“wrapped”) by a KMS master key. The encrypted file and wrapped data key can be stored together safely; the plaintext data key is discarded after use. Only the small, long-lived master key needs strong hardware-backed protection because it unlocks the data keys, not every large file directly.

### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot in the cloud? 
  Cryptographic erasure destroys or disables the key needed to decrypt encrypted data. The remaining ciphertext may still exist in backups, replicas, or cloud storage, but it becomes computationally unreadable because the decryption key is unavailable. Overwriting is less reliable in cloud environments because data may have multiple copies outside the user’s direct control.

### Q5. How does a hash chain make a log tamper-evident?
  In a hash chain, every log entry includes the hash of the previous entry. Changing one earlier entry changes its hash, which then breaks the link to every later entry. This makes tampering detectable when the expected final hash or a trusted checkpoint is retained separately.

## Security best-practices checklist

- [x] Use AES-256 with a salt and PBKDF2 for password-based file encryption.
- [x] Use a unique data-encryption key for envelope encryption and keep the KMS-wrapped copy.
- [x] Keep private keys and plaintext data keys out of shared folders, source control, and logs.
- [x] Verify digital signatures before trusting received files.
- [x] Use TLS for data in transit; validate certificates in production.
- [x] Apply least-privilege KMS permissions and enable key-use audit logging.
- [x] Treat key deletion as a controlled change with a waiting period and recovery owner.
- [x] Protect integrity baselines; an attacker must not be able to alter both a file and its reference hash.
- [ ] Replace lab passwords, self-signed certificates, and shell-held key values before any real deployment.

## Lessons learned

The lab made the distinction between cryptographic functions much clearer. Encryption protected the record from being read, while the signature gave confidence that it had not been changed. The KMS exercises also made key management feel less abstract: losing or disabling a key can make otherwise intact ciphertext unusable. The most practical takeaway is that strong algorithms are only part of the solution; how keys are generated, stored, rotated, authorised, audited, and retired determines whether the protection holds up in real use.

## Conclusion

This lab demonstrated a complete, small-scale protection workflow: encrypt sensitive data, verify its integrity, transport it over TLS, and manage keys through KMS. AES, RSA, TLS, KMS, and SHA-256 each address different security needs, and they are strongest when used together with careful key handling and operational controls. The evidence confirms successful encryption, decryption, signature verification, HTTPS retrieval, KMS envelope encryption, lifecycle enforcement, and tamper detection.
