# IKB42603 Cloud Computing Security Essentials
## Lab 5: Monitoring, Logging & Incident Detection

**Name:** Affiq
**Student ID:** 52215124425

## 1. Objective

To implement a small monitoring and incident-detection workflow: collect application authentication events centrally, identify suspicious activity, protect the integrity of the log evidence, correlate the events into an incident, contain the source, and verify that the evidence remains available.

## 2. Learning Outcomes

After completing this lab, I am able to:

1. Create structured application logs containing a timestamp, event type, username, source IP address, and relevant details.
2. Send log events to a central log service and query them.
3. Detect repeated authentication failures from a single IP address.
4. Use SHA-256 hashes to make tampering with log evidence detectable.
5. Correlate a brute-force attempt, successful login, and large data export into a security incident.
6. Apply a simple network containment rule and preserve verifiable evidence.

## 3. Environment

| Component | Purpose |
| --- | --- |
| Kali Linux terminal | Creates, analyses, and protects the test logs. |
| `aws` CLI | Sends and retrieves CloudWatch Logs events. |
| Local CloudWatch-compatible endpoint (`http://localhost:4566`) | Used for local log-group verification. |
| Docker with Alpine Linux | Applies the test `iptables` containment rule. |
| Shell utilities | `cat`, `grep`, `awk`, `sort`, `uniq`, `sha256sum`, and `date`. |

The scenario concerns the suspicious public address `203.0.113.9`. The address is a documentation-range IP used safely as an example.

## 4. Step-by-Step Implementation

### Task 1 — Create structured authentication logs

The following command writes a realistic authentication log. Structured `key=value` fields make the log easier to search and correlate than unstructured sentences.

```bash
cat > auth.log << 'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF

cat auth.log
```

The output shows four failed `admin` logins from `203.0.113.9`, followed by a successful login from the same address and a 500 MB export. This sequence is intentionally suspicious.

**Result:** The `auth.log` file was created successfully. It contains four `LOGIN_FAIL` events for `admin` from `203.0.113.9`, followed by a successful login and a `500MB` export from the same IP.

![Task 1 – create and display the authentication log](Task%201.png)

### Task 2 — Ingest and retrieve central log events

First create the log group and stream when they do not already exist. The timestamp sent to CloudWatch Logs must be in milliseconds, so `TS` begins with the current epoch time multiplied by 1,000. One second is added per event so every event has a distinct timestamp.

```bash
aws logs create-log-group --log-group-name /ccse/app
aws logs create-log-stream --log-group-name /ccse/app --log-stream-name auth

TS=$(date +%s%3N)  # milliseconds
while IFS= read -r line; do
  aws logs put-log-events \
    --log-group-name /ccse/app \
    --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" > /dev/null
  TS=$((TS + 1000))  # add 1 second between events
done < auth.log

aws logs get-log-events \
  --log-group-name /ccse/app \
  --log-stream-name auth \
  --query 'events[].message' --output text
```

This task centralizes the locally generated events. The retrieval command confirms that the sent messages can be read back and that the log sequence was not lost during ingestion.

**Result:** All seven events were uploaded to `/ccse/app` and retrieved from the `auth` stream. The displayed messages match the original authentication log.

![Task 2 – upload and retrieve log events](Task%202.png)

### Task 3 — Detect repeated failed logins

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

`grep` keeps only failed-login records. `awk` extracts the account and IP fields, `sort` places matching values next to each other, and `uniq -c` counts them. The observed result is `4 ip=203.0.113.9`, which indicates four failed authentication attempts from the suspicious source.

**Result:** `4 ip=203.0.113.9` confirms that the suspicious IP produced four failed logins.

![Task 3 – failed-login count](Task%203.png)

### Task 4 — Build a tamper-evident hash chain and simulate tampering

```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain

cat auth.chain

sed 's/500MB/5MB/' auth.log > auth.tampered
cat auth.tampered
```

Each hash includes the previous hash and the current event. Therefore, changing any event changes its hash and every later hash. The `sed` command creates a separate altered copy, changing the export size from `500MB` to `5MB`; it does not overwrite the original `auth.log`.

**Result:** `auth.chain` contains a SHA-256 value for each original log record. The tampered file shows `size=5MB`, so the modification can be detected by checking the hash values.

![Task 4 – hash chain and tampered copy](Task%204.png)

### Task 5 — Correlate the incident and generate an alert

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo "ALERT: probable brute-force -> compromise -> data exfiltration"
fi
```

The correlation rule requires at least three failures, one successful login, and one export event from the same source. The observed values are `fails=4`, `success=1`, and `export=1`; consequently, the alert correctly classifies the sequence as probable brute force, compromise, and data exfiltration.

**Result:** The alert `probable brute-force -> compromise -> data exfiltration` is generated because all three conditions are true.

![Task 5 – correlation result and alert](Task%205.png)

### Task 6 — Contain the source and preserve evidence

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  "apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2"

cp auth.log "evidence_$(date +%Y%m%d).log"
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

The Docker command isolates the firewall test in a short-lived Alpine container, adds a rule that drops input from `203.0.113.9`, and lists the rule. The evidence command copies the original log with a date-based name, then writes a SHA-256 manifest. The screenshot shows `evidence_20260906.log` and its corresponding digest.

**Result:** The firewall shows a `DROP` rule for `203.0.113.9`. The evidence log was preserved and its SHA-256 hash was written to `evidence.sha256`.

![Task 6 – block source and hash evidence](Task%206.png)

## 5. Commands Used

### Task 1

```bash
cat auth.log
```

### Task 2

```bash
EP='--endpoint-url=http://localhost:4566'
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth
```

### Task 3

```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

### Task 4

```bash
sha256sum
sed 's/500MB/5MB/' auth.log > auth.tampered
```

### Task 5

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo "ALERT: probable brute-force -> compromise -> data exfiltration"
fi
```

### Task 6

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  "apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2"

cp auth.log "evidence_$(date +%Y%m%d).log"
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```

## 6. Screenshots

### Task 1

Insert screenshot showing the generated `auth.log`.

![Task 1 - generated auth.log](Task%201.png)

### Task 2

Insert screenshot showing log events uploaded to and retrieved from `/ccse/app`.

![Task 2 - CloudWatch log ingestion](Task%202.png)

### Task 3

Insert screenshot showing the failed-login count for the suspicious IP address.

![Task 3 - failed-login detection](Task%203.png)

### Task 4

Insert screenshot showing the hash chain and the tampered log file.

![Task 4 - hash chain and tampered log](Task%204.png)

### Task 5

Insert screenshot showing the correlated incident counts and alert message.

![Task 5 - incident-correlation alert](Task%205.png)

### Task 6

Insert screenshot showing the firewall `DROP` rule and the generated evidence hash.

![Task 6 - containment and evidence preservation](Task%206.png)

## 7. Challenges Encountered

1. **Cloud log timestamp format:** CloudWatch Logs expects milliseconds, not seconds. This was handled with `date +%s%3N` and a 1,000 ms increment for each event.
2. **Event ordering:** Events with the same timestamp can be difficult to order. Incrementing `TS` preserves the intended sequence.
3. **Noisy command output:** The upload command redirects normal output to `/dev/null`, keeping the terminal focused on the final verification.
4. **Evidence integrity:** A normal text file can be edited silently. The hash chain and the `evidence.sha256` manifest make later changes detectable.
5. **Safe containment testing:** Changing the host firewall could disrupt the lab machine. Docker confines the sample rule to a disposable container.

## 8. Lessons Learned

Central logging is useful only when events have consistent fields and can be queried. A count of failed logins alone is an indicator, but the combination of failures, a successful login, and a subsequent large export has much stronger incident value. Integrity controls are also essential: monitoring evidence should be protected before it is relied on for investigation. Finally, containment should be targeted and verified so that the response reduces risk without unnecessarily affecting legitimate users.

## 9. Short-Answer Questions

## Q1. What is the difference between a log and an event?

**Answer:**

A log is a stored record the `LOGIN_FAIL` line, whereas an event is an actionable real-time alert (the exfiltration alert).

## Q2. Why must audit logs be tamper-proof?

**Answer:**

Logs must be tamper-proof to prevent attackers from covering tracks. Hash-chaining links each entry so modifying anything breaks the chain and changes the final hash.

## Q3. How did correlation detect the incident?

**Answer:**

Single lines appear harmless, but correlating events by IP `203.0.113.9` uncovered the full sequence: 4 failed attempts, 1 successful breach, and 1 large data export.

## Q4. List the incident-response steps performed.

**Answer:**

The steps were **detection** (flagging the attack pattern), **containment** (dropping the IP with `iptables`), **evidence collection** (hashing and saving log copies), and **documentation** (incident reporting).

## Q5. How can logs be used for security and compliance?

**Answer:**

Centralized logs feed real-time threat detection (monitoring) while immutable, hashed logs provide audit trails required by regulators (compliance).

## Security Best-Practices Checklist

- [x] Logs are centralised.
- [x] Failed login activity can be queried.
- [x] Logs are tamper-evident using a hash chain.
- [x] Multiple events are correlated to detect an incident.
- [x] The attacker is contained.
- [x] Evidence is collected and hashed.
- [x] The incident is documented.

## 10. Verification Command

The lab verifies both central logging and evidence integrity with:

```bash
aws --endpoint-url=http://localhost:4566 logs describe-log-groups
sha256sum -c evidence.sha256
```

The first command confirms that `/ccse/app` exists in the local log service. The second command compares the current evidence file against the stored digest. The observed output, `evidence_20260906.log: OK`, confirms that the evidence file matches the SHA-256 value recorded at preservation time.

![Verification – log group and evidence hash](Verification%20Command.png)

## 11. References

1. Amazon Web Services, *AWS CLI Command Reference — CloudWatch Logs*: <https://docs.aws.amazon.com/cli/latest/reference/logs/>.
2. GNU Coreutils, *`sha256sum` invocation*: <https://www.gnu.org/software/coreutils/manual/html_node/sha2-utilities.html>.
3. Netfilter Project, *iptables documentation*: <https://www.netfilter.org/documentation/>.
4. Docker Docs, *Docker run reference*: <https://docs.docker.com/engine/containers/run/>.
