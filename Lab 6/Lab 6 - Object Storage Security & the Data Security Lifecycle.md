# IKB42603 Cloud Security Essentials

### Lab 6: Object Storage Security: S3 Access Control, Encryption & Lifecycle Posture

**Name:** Affiq
**Student ID:** 52215124425
**Lecturer:** Madam Adani

---

## Objective

To securely provision and manage an Amazon S3-compatible object-storage bucket on LocalStack across its full data lifecycle: classify stored data, demonstrate and remediate public exposure, enforce least privilege and encryption, understand temporary delegated access, manage versioned data and retention, and perform cryptographic erasure.

## Learning Outcomes

At the end of this lab, I was able to:

- Classify objects before storing them and apply classifications using object tags.
- Reproduce a public-bucket data exposure and remediate it with Block Public Access and least-privilege policies.
- Differentiate IAM identity policies from S3 resource policies and apply explicit-deny precedence.
- Configure default SSE-KMS encryption and verify it at object level.
- Explain presigned URL access, expiration, and the `aws:SecureTransport` condition-key trap in a HTTP LocalStack environment.
- Use versioning, lifecycle rules, and KMS key deletion to manage retention, remanence, and provable deletion.

## Environment

| Component | Configuration |
|---|---|
| Operating environment | Kali Linux terminal (as shown in submitted evidence) |
| Object-storage emulator | LocalStack, Docker container on `http://localhost:4566` |
| CLI | AWS CLI v2 |
| Services used | S3-compatible API, IAM, and KMS |
| Endpoint variable | `EP='--endpoint-url=http://localhost:4566'` |
| Bucket | `miit-patient-records-$RANDOM` (actual suffix is intentionally variable) |
| Region / credentials | `us-east-1`; LocalStack test credentials |

## Data Classification

| Classification | Who may read it | Impact if leaked | Control implemented |
|---|---|---|---|
| Public | Anyone | Low; information is intended for public viewing. | `classification=public` tag; stored under `public/`. |
| Internal | Authorised hospital staff / own AWS account | Operational information may be exposed or misused. | Prefix-scoped least-privilege bucket policy for `internal/*`. |
| Confidential | Only explicitly authorised personnel | High; exposes patient identity and diagnosis, creating privacy and regulatory risk. | `classification=confidential` tag, Block Public Access, explicit deny, SSE-KMS, versioning, lifecycle, and cryptographic erasure. |

## Step-by-Step Implementation

### Task 1 — Classify data before storage

Created a hospital-records bucket, created public, internal and confidential files, uploaded them under prefix-style keys, and attached a classification tag to every object. Object storage is flat: `confidential/record.txt` is a key, not a real folder.

```bash
export BUCKET=miit-patient-records-$RANDOM
aws $EP s3api create-bucket --bucket $BUCKET
echo 'Ward visiting hours 8am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt
aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt --body public-notice.txt --tagging 'classification=public'
aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt --body internal-roster.txt --tagging 'classification=internal'
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body confidential-record.txt --tagging 'classification=confidential'
aws $EP s3api list-objects-v2 --bucket $BUCKET --query 'Contents[][Key, Size]' --output table
aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

Result: the bucket listed `confidential/record.txt`, `internal/roster.txt`, and `public/notice.txt`, each 29 bytes. The confidential object's tag was `classification=confidential`.

### Task 2 — Reproduce a public-bucket breach

Applied a policy with `"Principal": "*"`, allowing unauthenticated `s3:GetObject` access to every object, then read the confidential record using only `curl`.

```bash
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

Result: `HTTP 200` was returned and the terminal displayed `Patient: Ahmad bin Ali, Diagnosis: confidential`.

### Task 3 — Remediate exposure

Deleted the public policy and enabled all four Block Public Access flags. The result was inspected, then anonymous access was retested. A least-privilege policy was prepared for only the account root and only `internal/*`.

```bash
aws $EP s3api delete-bucket-policy --bucket $BUCKET
aws $EP s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws $EP s3api get-public-access-block --bucket $BUCKET
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' http://localhost:4566/$BUCKET/confidential/record.txt
```

Result: all four flags were `true`. LocalStack retained the configuration but still returned `HTTP 200` for the anonymous test, a documented emulator limitation. On AWS, `BlockPublicPolicy=true` rejects a public bucket policy; `RestrictPublicBuckets=true` restricts public-policy access. This preventative guardrail is stronger than a detective control because it prevents the unsafe change instead of merely detecting it afterwards.

### Task 4 — IAM policy versus resource policy

Created `DataAnalyst`, attached an identity policy permitting reads, then attached a resource policy that allows the analyst to read `internal/*` but explicitly denies access to `confidential/*`.

```bash
aws $EP iam create-user --user-name DataAnalyst
aws $EP iam put-user-policy --user-name DataAnalyst --policy-name S3ReadAll --policy-document file://analyst-iam.json
aws $EP iam create-access-key --user-name DataAnalyst --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://deny-confidential.json
aws --profile analyst $EP s3api get-object --bucket $BUCKET --key internal/roster.txt analyst-internal.txt && echo ALLOWED
aws --profile analyst $EP s3api get-object --bucket $BUCKET --key confidential/record.txt analyst-conf.txt || echo 'confidential: DENIED'
```

Result: the submitted policy evidence shows the allow statement for `internal/*` and explicit deny statement for `confidential/*`. The expected evaluation is internal allowed (both policies allow it) and confidential denied (the resource-policy explicit deny overrides the IAM allow). If LocalStack was not launched with `ENFORCE_IAM=1`, it may permit both; this is an emulator limitation rather than correct AWS authorization behaviour.

### Task 5 — Enable default SSE-KMS encryption

Configured the bucket to use a dedicated KMS key for default encryption, uploaded a new confidential object with no encryption flag, and inspected it.

```bash
export KEY_ID=$(aws $EP kms create-key --description 'IKB42603 Lab6 patient records bucket key' --query 'KeyMetadata.KeyId' --output text)
aws $EP s3api put-bucket-encryption --bucket $BUCKET --server-side-encryption-configuration file://encryption.json
aws $EP s3api put-object --bucket $BUCKET --key confidential/record-v2.txt --body confidential-record.txt
aws $EP s3api head-object --bucket $BUCKET --key confidential/record-v2.txt --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

Result: the upload response reported `ServerSideEncryption: aws:kms` and `BucketKeyEnabled: true`; `head-object` reported `aws:kms` and `True`. The bucket therefore encrypted an upload even though the uploader did not request encryption.

### Task 6 — Delegated access and the SecureTransport condition

Created a 60-second presigned URL, tested it before and after expiry, then applied a deny rule for requests where `aws:SecureTransport=false`.

```bash
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
curl -s -w 'HTTP %{http_code}\n' "$URL"
sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://secure-transport.json
aws $EP s3api list-objects-v2 --bucket $BUCKET
aws $EP s3api delete-bucket-policy --bucket $BUCKET
```

Result: the SecureTransport policy was applied, then removed for recovery. The screenshot records a shell `bad pattern` during one attempt, after which `put-bucket-policy` succeeded and objects could again be listed. The condition is unsafe for the LocalStack endpoint because it uses plain HTTP, so `aws:SecureTransport` is false for every request; the same policy is appropriate on real AWS HTTPS endpoints. A presigned URL contains expiry information (`Expires` or `X-Amz-Expires`) and a signature binding the allowed request; anyone holding it before expiry is authorised for that specific access.

### Task 7 — Versioning, delete markers and remanence

Enabled versioning, uploaded revised records, deleted the object, listed the delete marker, and inspected versions.

```bash
aws $EP s3api put-bucket-versioning --bucket $BUCKET --versioning-configuration Status=Enabled
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body rec-v2.txt --query VersionId --output text
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body rec-v3.txt --query VersionId --output text
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt
aws $EP s3api list-object-versions --bucket $BUCKET --prefix confidential/record.txt --query 'DeleteMarkers[][VersionId,IsLatest]' --output table
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt --version-id null recovered.txt
cat recovered.txt
```

Result: versioning status was `Enabled`; the delete operation created a latest delete marker rather than erasing earlier versions. The version list showed retained records, including version ID `null` from before versioning. This demonstrates object-level data remanence.

### Task 8 — Lifecycle, retention and cryptographic erasure

Applied lifecycle rules to expire confidential records after 365 days and non-current versions after 30 days, then disabled and scheduled deletion of the KMS key.

```bash
aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET --lifecycle-configuration file://lifecycle.json
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET --query 'Rules[][ID,Status]' --output table
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.[KeyState,DeletionDate]' --output text
```

Result: the key entered `PendingDeletion` state with a seven-day pending window. The verification output showed both lifecycle rules enabled: `RetireConfidentialRecords` and `AbortIncompleteUploads`.

## Commands Used

| Area | Main commands used | Purpose |
|---|---|---|
| Object classification | `s3api create-bucket`, `put-object`, `list-objects-v2`, `get-object-tagging` | Create, tag, and verify objects. |
| Exposure test | `put-bucket-policy`, `curl` | Intentionally expose and anonymously retrieve an object. |
| Public-access remediation | `delete-bucket-policy`, `put/get-public-access-block` | Remove exposure and configure guardrails. |
| Authorisation | `iam create-user`, `put-user-policy`, `create-access-key`, `get-object` | Test identity and resource policies. |
| Encryption | `kms create-key`, `put/get-bucket-encryption`, `head-object` | Enable and verify SSE-KMS. |
| Delegated access | `s3 presign`, `curl` | Issue and test time-bounded URL access. |
| Versioning | `put/get-bucket-versioning`, `list-object-versions`, `delete-object` | Demonstrate delete markers and remanence. |
| Retention/erasure | `put/get-bucket-lifecycle-configuration`, `kms disable-key`, `kms schedule-key-deletion` | Automate retention and invalidate encrypted data. |
| Cleanup | `delete-objects`, `delete-bucket`, `iam delete-user-policy`, `iam delete-user` | Remove versions, bucket, IAM user, and LocalStack. |

## Screenshots and Findings

### Screenshot 1 — Task 1: Object list and confidential tag

![Task 1](Task%201.png)

Finding: Three classified objects were present. The confidential record had the tag `classification=confidential`, confirming classification occurred before access controls were applied.

### Screenshot 2 — Task 2: Anonymous disclosure

![Task 2](Task%202.png)

Finding: An unauthenticated `curl` request returned `HTTP 200` and disclosed the patient record. This proves a publicly readable bucket is a data breach without needing an exploit.

### Screenshot 3 — Task 3: Block Public Access

![Task 3](Task%203.png)

Finding: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` were all true. LocalStack nevertheless returned HTTP 200 after the attempted policy reapplication, so configuration evidence rather than enforcement output demonstrates the guardrail in this emulator.

### Screenshot 4 — Task 4: Policy evidence

![Task 4](Task%204.png)

Finding: The resource policy contains an allow for the analyst on `internal/*` and an explicit deny on `confidential/*`. Explicit deny must win over the analyst's broad IAM allow.

### Screenshot 5 — Task 5: SSE-KMS verification

![Task 5](Task%205.png)

Finding: The object upload and `head-object` output show `aws:kms` encryption and `BucketKeyEnabled: true`, confirming bucket-default SSE-KMS was used.

### Screenshot 6 — Task 6: SecureTransport policy

![Task 6](Task%206.png)

Finding: The TLS-only deny policy was created and later removed. The displayed shell-pattern error illustrates an execution issue corrected by rerunning the policy command; the policy must be evaluated against LocalStack's HTTP endpoint before use.

### Screenshot 7 — Task 7: Versioning and delete marker

![Task 7](Task%207.png)

Finding: Versioning was enabled and a current delete marker was created. Historical versions remained, proving a normal delete does not eliminate retained data.

### Screenshot 8 — Task 8: Key scheduled for deletion

![Task 8](Task%208.png)

Finding: The KMS key was disabled and transitioned to `PendingDeletion` with a seven-day deletion window. Destroying the wrapping key makes ciphertext unrecoverable after deletion.

### Screenshot 9 — Final verification

![Verification command](Verification%20Command.png)

Finding: Verification reported all public-access-block flags true, versioning enabled, SSE-KMS enabled, both lifecycle rules enabled, and the key in `PendingDeletion` state.

### Screenshot 10 — Cleanup and teardown

![Cleanup and teardown](cleanup%20%26%20teardown.png)

Finding: Objects were removed before teardown. An error on a later deletion query occurred because no remaining versions produced a `None` object list; this is consistent with the bucket already being empty. IAM cleanup and LocalStack removal commands were then issued.

## Short-Answer Questions

### 1. Exposure cause and risk of `Principal: "*"`

The single element causing the exposure was `"Principal": "*"`. It grants the policy to every principal, including anonymous internet users, so anyone who knows or guesses an object URL can make the permitted request. It is more dangerous in a bucket policy than an over-broad policy attached to one IAM user because it changes access at the resource boundary for an unlimited, unauthenticated audience instead of only expanding the permissions of one identified account principal.

### 2. Identity-based versus resource-based policies

| Policy type | Attached to | What it controls | Task 4 outcome |
|---|---|---|---|
| Identity-based policy | An IAM user, group, or role | What that caller may request across resources. | The analyst IAM policy allowed reads. |
| Resource-based policy | The S3 bucket | Who may access that bucket and which keys/actions they may use. | It allowed the analyst to read `internal/*` and explicitly denied `confidential/*`. |

For the internal request, both policies allowed access, so it was allowed. For the confidential request, the resource policy's explicit `Deny` decided the result and overrides the IAM `Allow`.

### 3. Guardrail versus control

A detective control identifies or reports an unsafe state after it exists, such as a scanner reporting a public bucket. A guardrail is a preventative control that stops the unsafe configuration from being created. Block Public Access is a guardrail because it overrides attempts to make a bucket public. In an organisation with many engineers, this matters because it protects against ordinary mistakes at scale and reduces reliance on every individual remembering every security rule.

### 4. Does SSE-KMS protect the record from the analyst?

No, not by itself. SSE-KMS encrypts data at rest: S3 encrypts the object before storage and decrypts it for an authorised read using the KMS key under the service's control path. It protects stored media, lost disks, and unauthorised low-level access to ciphertext. It does not replace authorisation. A principal permitted by S3 and KMS-related permissions can receive the plaintext; therefore resource and identity policies are still required to deny the analyst's confidential read.

### 5. Right to erasure and provable deletion

`delete-object` alone is insufficient because Task 7 showed it writes a delete marker while earlier object versions, including the original record, remain retrievable by version ID. Two mechanisms for provable deletion are:

1. Permanently delete every object version and delete marker by its version ID, then retain the empty `list-object-versions` evidence.
2. Use lifecycle expiration/non-current-version expiration for scalable automated removal, combined where appropriate with cryptographic erasure: disable and schedule deletion of the KMS key that encrypts all versions. Once the key is destroyed, remaining ciphertext is computationally unrecoverable.

### 6. Three commands an auditor would collect

| Command | Compliance evidence / control |
|---|---|
| `aws $EP s3api get-public-access-block --bucket $BUCKET` | All four public-access prevention guardrails are enabled. |
| `aws $EP s3api get-bucket-encryption --bucket $BUCKET` | Default encryption at rest is SSE-KMS with the configured key. |
| `aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET` | Retention, expiration, and incomplete-upload cleanup are defined as auditable lifecycle rules. |
| `aws $EP s3api get-bucket-versioning --bucket $BUCKET` | Versioning is enabled, supporting recovery and explaining the version-deletion requirement. |
| `aws $EP kms describe-key --key-id $KEY_ID` | KMS key state and scheduled cryptographic-erasure evidence. |

## Final Verification Result

The supplied verification screenshot confirms the intended final posture: all Public Access Block values were true, versioning was `Enabled`, default encryption was `aws:kms`, lifecycle rules `RetireConfidentialRecords` and `AbortIncompleteUploads` were `Enabled`, and the KMS key state was `PendingDeletion`.

## Challenges Encountered

| Challenge | Evidence / cause | Resolution or lesson |
|---|---|---|
| Block Public Access was not fully enforced by LocalStack | Task 3 still returned `HTTP 200` despite all flags being true. | Record the configuration as evidence; on AWS, the public policy would be blocked. Test critical controls in the real target environment. |
| IAM policy evaluation may not be enforced | Task 4 behaviour depends on LocalStack starting with `ENFORCE_IAM=1`. | Use the flag and document formal AWS evaluation: explicit deny overrides allow. |
| SecureTransport deny can lock out local CLI calls | LocalStack endpoint is HTTP, making `aws:SecureTransport=false`. | Remove the policy to recover; validate condition keys against the deployment environment. |
| Shell `bad pattern` error | Shown while handling the SecureTransport policy. | Correct/re-run the command and verify policy state before continuing. |
| Cleanup delete query returned `None` | No versions remained when a delete-objects call was attempted. | Treat this as empty-state evidence; only submit a non-empty object list to `delete-objects`. |

## Lessons Learned

- Data classification must be performed before configuring storage and access because sensitivity determines the appropriate controls.
- A bucket policy with `Principal: "*"` can expose every matching object to the internet immediately.
- Preventative guardrails, least privilege, and explicit denies are complementary: encryption cannot compensate for incorrect authorisation.
- Default SSE-KMS removes reliance on developers remembering per-upload encryption settings.
- A presigned URL is a bearer credential; anyone who holds it before expiry can use the access it grants.
- Versioned deletion creates a delete marker rather than data destruction. Lifecycle management and per-version deletion are necessary for retention compliance.
- Cryptographic erasure provides strong deletion assurance when physical cloud media cannot be directly controlled.

## References

1. IKB42603 Cloud Computing Security Essentials, *Lab 6: Object Storage Security and the Data Security Lifecycle* (provided lab manual).
2. [Amazon S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html).
3. [Amazon S3 Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html).
4. [Amazon S3 lifecycle configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html).
5. [AWS KMS key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html).
6. [LocalStack S3 coverage and limitations](https://docs.localstack.cloud/references/coverage/coverage_s3/).
