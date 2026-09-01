# Lab 4: Access Control and Network Security

**Name:** Affiq  
**Student ID:** 52215124425  
**Lab:** L02-B04  
**Course:** IKB42603  

## Objective

To implement and verify authentication, multi-factor authentication (MFA), authorization, network segmentation, default-deny firewall rules, and container hardening with Docker and Kubernetes. The lab demonstrates defence in depth: validate identity, grant only required permissions, restrict network paths, and reduce the exposed attack surface.

## Learning Outcomes

After completing this lab, I can:

- Distinguish authentication (AuthN) from authorization (AuthZ) and implement both.
- Generate and validate a time-based one-time password (TOTP) as a second factor.
- Apply Kubernetes RBAC using a least-privilege role.
- Segment Docker networks so tiers can communicate only where required.
- Model a default-deny firewall policy with an explicit HTTPS allow rule.
- Harden a container with a non-root user, read-only filesystem, dropped capabilities, and no-new-privileges.

## Environment

| Component | Use in this lab |
| --- | --- |
| Kali Linux terminal | Command-line environment shown in the evidence |
| Docker | Containers, networks, firewall demonstration, and hardening |
| Nginx / Redis / Alpine images | Web service, application, database, and utility containers |
| kind and kubectl | Local Kubernetes cluster and RBAC validation |
| `oathtool` | Generation and validation of the TOTP code |
| Trivy | Image vulnerability scanning (required command listed below) |

## Step-by-Step Implementation

### Task 1 — Password-Protected Service (Authentication)

I created an HTTP Basic Authentication password file for user `student`, mounted it together with an Nginx configuration, and started the service on port 8080. The request without credentials returned `401`, while the request with valid credentials returned `Authenticated OK`. This proves that the service verifies the caller's identity before granting access.

#### Commands Used

```bash
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt

cat > default.conf <<'EOF'
server {
  listen 80;
  location / {
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
    return 200 'Authenticated OK\n';
  }
}
EOF

docker run --rm -d --name authsvc -p 8080:80 \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd nginx

curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
curl -s -u student:'P@ssw0rd!' http://localhost:8080
```

**Result:** `no-creds: 401` followed by `Authenticated OK` for valid credentials.

#### Screenshot

![Task 1: 401 without credentials and authenticated success with valid credentials](screenshots_redacted/Task%201_redacted.png)

### Task 2 — MFA with TOTP

I generated a base32 shared secret, generated its current six-digit TOTP value, and compared the code entered by the user with the expected value. The evidence shows `MFA OK`, confirming that the entered time-based code was valid. The secret and one-time code are redacted because they are sensitive authentication material.

#### Commands Used

```bash
SECRET=$(head -c20 /dev/urandom | base32)
echo "Enrol this secret in an authenticator app: $SECRET"
oathtool --totp -b "$SECRET"

read -p 'Enter the 6-digit code: ' CODE
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

**Result:** A valid six-digit code produced `MFA OK`.

#### Screenshot

![Task 2: MFA validation succeeded; secret and one-time code redacted](screenshots_redacted/Task%202_redacted.png)

### Task 3 — Kubernetes RBAC Authorization

I created an `app` namespace, a `dev` service account, and a role limited to `get` and `list` operations on pods. The role binding assigned only that role to the service account. Kubernetes authorization checks confirmed that listing pods is allowed, while deploying and deleting pods are denied.

#### Commands Used

```bash
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app

kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app \
  --role=dev-role --serviceaccount=app:dev

SA=system:serviceaccount:app:dev
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

**Result:** `yes` for listing pods; `no` for creating deployments and deleting pods. This applies the principle of least privilege.

#### Screenshot

![Task 3: pod list allowed; deployment creation and pod deletion denied](screenshots_redacted/Task%203_redacted.png)

### Task 4 — Three-Tier Network Segmentation

I created separate `frontend-net` and `backend-net` Docker networks. The database was connected only to the backend network. The application was connected to both networks, while the web container was connected only to the frontend network. Therefore, web-to-database communication was blocked, but application-to-database communication was reachable.

#### Commands Used

```bash
docker network create frontend-net
docker network create backend-net

docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx

docker exec web sh -c 'apk add -q curl; curl -s -m 3 db:6379 || echo BLOCKED'
docker exec app sh -c 'apk add -q curl; nc -z -w3 db 6379 && echo REACHABLE'
```

**Result:** `web → db` was `BLOCKED`; `app → db` was `REACHABLE`.

#### Screenshots

![Task 4a: frontend and backend Docker networks created](screenshots_redacted/Task%204.0_redacted.png)

![Task 4b: web-to-database access blocked](screenshots_redacted/Task%204.1_redacted.png)

![Task 4c: application-to-database access reachable; internal IP redacted](screenshots_redacted/Task%204.2_redacted.png)

### Task 5 — Default-Deny Firewall Rules

Inside a temporary privileged-for-networking Alpine container, I set the `INPUT` chain policy to `DROP`, then added explicit rules allowing TCP port 443 and loopback traffic. The resulting ruleset shows a default-deny policy with only the intended inbound traffic permitted.

#### Commands Used

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
  apk add -q iptables;
  iptables -P INPUT DROP;
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT;
  iptables -A INPUT -i lo -j ACCEPT;
  iptables -L INPUT -n'
```

**Result:** The `INPUT` policy is `DROP`; TCP destination port 443 and the loopback interface have explicit `ACCEPT` rules.

#### Screenshot

![Task 5: INPUT default-deny with HTTPS and loopback explicitly allowed](screenshots_redacted/Task%205_redacted.png)

### Task 6 — Container and Host Hardening

I ran Nginx as an unprivileged user, used a read-only root filesystem, dropped all Linux capabilities, prevented privilege escalation, and supplied a temporary writable `/tmp` filesystem. The inspection output confirms `User=1000:1000`, `ReadOnly=true`, and an empty capability-drop exception list (`CapDrop=[ALL]`). The unprivileged numeric user ID is redacted in the report screenshot.

#### Commands Used

```bash
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}}'

docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

**Result:** The supplied screenshot confirms the non-root user, read-only root filesystem, and `CapDrop=[ALL]`. The Trivy command is included as the required vulnerability-scanning step; no Trivy scan output screenshot was supplied.

#### Screenshot

![Task 6: non-root user ID redacted; read-only filesystem and all capabilities dropped](screenshots_redacted/Task%206_redacted.png)

### Verification and Cleanup Commands

```bash
kubectl get rolebinding dev-rb -n app -o yaml
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'

docker rm -f authsvc db app web hardened 2>/dev/null
docker network rm frontend-net backend-net 2>/dev/null
kind delete cluster --name ccse-lab4
```

## Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

Authentication establishes who a requester is. In Task 1, Nginx accepts the request only when the supplied username and password match the password file; without credentials it returns HTTP 401. Authorization establishes what an already identified requester may do. In Task 3, the `dev` service account is authorized to list pods but is denied permission to create deployments or delete pods because its RBAC role grants only `get` and `list` on pods.

### Q2. Why is MFA so effective, and which attacks does it defeat?

MFA requires an additional factor from a different category: here, a password (something known) and a TOTP code from an authenticator device (something possessed). A stolen or guessed password alone is therefore insufficient. MFA strongly reduces the success of password guessing, password spraying, credential stuffing, and reuse of credentials leaked in a breach. It also limits many phishing attacks, although real-time adversary-in-the-middle phishing can still relay a TOTP; phishing-resistant factors such as passkeys provide stronger protection against that case.

### Q3. How does network segmentation limit the damage of a compromised web server?

The public-facing web container is placed only on `frontend-net`, while the database is only on `backend-net`. If an attacker compromises the web server, it cannot directly resolve or connect to the database because there is no shared network path. The application is the controlled intermediary on both networks. This blocks a direct lateral-movement route and contains the compromise.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

Default-deny rejects inbound traffic unless a rule explicitly permits it. In this lab, the `INPUT` policy is `DROP`, with only HTTPS on TCP/443 and loopback traffic allowed. Cloud security groups use the same allow-list model: traffic is not exposed merely because a workload exists; each required protocol, port, source, and destination must be deliberately authorized.

### Q5. List the hardening measures applied and the attack surface each one removes.

| Hardening measure | Attack surface or risk reduced |
| --- | --- |
| `--user 1000:1000` | Limits the impact of a process compromise by preventing the service from running as root inside the container. |
| `--read-only` | Prevents modification of the container root filesystem, reducing persistence and tampering opportunities. |
| `--cap-drop=ALL` | Removes privileged Linux kernel operations that could otherwise be abused after compromise. |
| `--security-opt no-new-privileges` | Prevents processes from gaining extra privileges through setuid/setgid executables or similar mechanisms. |
| `--tmpfs /tmp` | Provides only ephemeral writable temporary storage instead of making the root filesystem writable. |
| Trivy image scan | Identifies known HIGH and CRITICAL package/image vulnerabilities for remediation before deployment. |

## Challenges Encountered

- The command output contains dynamic values such as image digests, container/network IDs, TOTP secrets/codes, and internal addresses. These values differ per run and were redacted in report copies to prevent disclosure.
- TOTP values are time-sensitive. A code can expire during testing, so the validation command must be run within the active time window or a fresh code must be generated.
- The three-tier test depends on correct Docker network membership. If the web container is attached to the backend network by mistake, the blocked test would no longer demonstrate segmentation.
- The Trivy command is documented as required, but its output was not present among the supplied screenshots; this report does not claim a scan result that was not evidenced.

## Lessons Learned

- Authentication and authorization solve different problems and should be implemented together.
- MFA makes a password-only compromise much less useful to an attacker.
- Least privilege applies consistently to RBAC permissions, firewall rules, network connectivity, and Linux capabilities.
- Segmentation and default-deny policies reduce lateral movement by making unintended access paths unavailable by default.
- Container hardening reduces the impact of a successful exploit, but image scanning is still necessary to find known vulnerable components.

## References

1. *IKB42603 Lab 4: Access Control and Network Security* (provided course handout), weeks 7–8.
2. [Docker Engine security documentation](https://docs.docker.com/engine/security/)
3. [Kubernetes RBAC authorization documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
4. [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
5. [Cloud Security Alliance: Security Guidance v5](https://cloudsecurityalliance.org/artifacts/security-guidance-v5)
