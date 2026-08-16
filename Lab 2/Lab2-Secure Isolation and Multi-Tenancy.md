# IKB42603 Cloud Computing Security Essentials

---

## Lab 2 - Secure Isolation & Multi-Tenancy

**Name:** Affiq  
**Student ID:** 52215124425  
**Environment:** Kali Linux, Docker Engine, kind, kubectl, and Calico

---

## Objective

This lab demonstrates secure multi-tenancy using Docker and Kubernetes. It covers compute isolation through namespaces and resource quotas, network isolation with Calico-enforced `NetworkPolicy`, storage and secret isolation using RBAC, and data remanence controls through secure deletion.

## 1. Learning objectives

By the end of this lab, I was able to:

1. Deploy and identify workloads belonging to separate tenants.
2. Demonstrate the default-open network posture inside a cluster.
3. Prevent a tenant from exhausting shared capacity with `ResourceQuota`.
4. Apply a default-deny network policy as a baseline for tenant network isolation.
5. Verify namespace-scoped secret permissions using Kubernetes RBAC.
6. Demonstrate data remanence and overwrite a deleted file before removal.

## 2. Security model

Kubernetes namespaces provide an administrative boundary, but they are not a complete security boundary on their own. A secure multi-tenant design combines multiple layers:

| Layer | Control used | Security purpose |
|---|---|---|
| Workload separation | Namespaces `tenant-a` and `tenant-b` | Separates names, policies and most scoped objects. |
| Availability | `ResourceQuota` | Stops one tenant from consuming excessive shared resources. |
| Network | Default-deny `NetworkPolicy` | Stops unapproved east-west traffic. |
| Identity and access | Service accounts and RBAC | Limits which tenant identities can read sensitive objects. |
| Data lifecycle | Secure overwrite before deletion | Reduces residual sensitive data on a shared volume. |

## 3. Task 1 — Two tenants on one cluster

### Objective

Confirm that both tenants have independent workloads and services while using the same Kubernetes cluster.

### Steps performed

1. Created or selected the `tenant-a` and `tenant-b` namespaces.
2. Deployed a web workload and a ClusterIP service in each namespace.
3. Listed the pods and services in each namespace:

```bash
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

### Result

`tenant-a` contained pod `web-7c56dcdb9b-zbvx4`, which was `1/1 Running`, and service `web` with ClusterIP `10.96.201.208` on port `80/TCP`. `tenant-b` contained a separate running pod, `web-7c56dcdb9b-9vf8t`, and its own `web` service with ClusterIP `10.96.153.133`.

This confirms logical separation: each namespace has a distinct service name resolution scope and workload inventory, despite both tenants sharing the cluster.

**Evidence:** `TASK 1 - Two Tenants on One Cluster.png`.

## 4. Task 2 — Demonstrate the default-open risk

### Objective

Show why namespaces alone do not prevent network access between tenants.

### Steps performed

1. Identified the ClusterIP of the service in `tenant-b`.
2. From `tenant-a`, launched a temporary curl pod and sent an HTTP request to the tenant B service:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://$B_IP -o /dev/null -w 'HTTP %{http_code}\n'
```

### Result

The request returned `HTTP 200`. This is successful cross-tenant connectivity from a workload in `tenant-a` to a service in `tenant-b`.

### Security interpretation

By default, Kubernetes networking is commonly flat: pods can communicate unless a network policy or another network control prevents it. Namespace separation should therefore be supplemented with explicit ingress and egress policy.

**Evidence:** `TASK 2 - Default-Open Risk.png`.

## 5. Task 3 — Enforce resource isolation with ResourceQuota

### Objective

Prevent tenant A from monopolising shared cluster resources.

### Steps performed

1. Applied a `ResourceQuota` named `tenant-a-quota` to namespace `tenant-a`.
2. The quota set these hard limits:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    pods: "5"
    requests.cpu: "1"
    requests.memory: 512Mi
```

3. Verified the active quota:

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

4. Attempted to create another pod with resource requests:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  --overrides='{"apiVersion":"v1","spec":{"restartPolicy":"Never","containers":[{"name":"probe","image":"curlimages/curl","resources":{"requests":{"cpu":"100m","memory":"64Mi"}}}]}}'
```

### Result

The quota reported a hard limit of five pods, one CPU core of requested CPU, and 512 MiB of requested memory. It showed one active pod and zero recorded requested CPU and memory at the time of inspection. The subsequent temporary workload did not become ready and ended with `error: timed out waiting for the condition`.

### Security interpretation

Resource quotas are an availability control. They help contain accidental or malicious overconsumption by a tenant. For predictable enforcement, all tenant workloads should define resource requests and limits, and quotas should be paired with `LimitRange` where appropriate.

**Evidence:** `TASK 3 - Resource Quota.png`.

## 6. Task 4 — Default-deny network isolation

### Objective

Establish a deny-by-default network posture for a tenant namespace.

### Steps performed

1. Applied a default-deny `NetworkPolicy` in `tenant-a`.
2. Retested access using the temporary curl probe with explicit CPU and memory requests.

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  --overrides='{"apiVersion":"v1","spec":{"restartPolicy":"Never","containers":[{"name":"probe","image":"curlimages/curl","resources":{"requests":{"cpu":"100m","memory":"64Mi"}}}]}}'
```

### Result

The probe was deleted and the command timed out waiting for its condition. This demonstrates that the attempted temporary workload did not obtain normal connectivity/operation under the controls in place.

### Security interpretation

A default-deny policy means traffic is rejected unless a separate allow policy explicitly permits it. In a production configuration, narrowly scoped allow rules would then be added for required DNS, ingress controller, monitoring, and approved application-to-application traffic. Policies must be supported and enforced by the cluster CNI; otherwise a `NetworkPolicy` object alone does not block traffic.

**Evidence:** `TASK 4 - Default-Deny Network Isolation.png`.

## 7. Task 5 — Storage and secret isolation

### Objective

Verify that a service account for tenant A can access secrets only in its assigned namespace.

### Steps performed

1. Used the service-account identity `system:serviceaccount:tenant-a:app-a`.
2. Tested whether that identity could read secrets in `tenant-a`:

```bash
kubectl auth can-i get secrets -n tenant-a --as=$SA
```

3. Tested the same permission against `tenant-b`:

```bash
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

### Result

The authorization check returned `yes` for `tenant-a` and `no` for `tenant-b`.

### Security interpretation

This confirms namespace-scoped RBAC enforcement for secrets. Tenant A's application identity can retrieve only the secrets granted within its own namespace. Sensitive credentials should be limited to the minimum necessary verbs and resources; cluster-wide roles should not be used for tenant applications unless strictly required.

**Evidence:** `TASK 5 - Storage and Secret Isolation.png`.

## 8. Task 6 — Data remanence and secure wipe

### Objective

Demonstrate that deleting a sensitive file does not necessarily address data remanence, then overwrite the file before removing it.

### Part A: Data remanence scan

1. Mounted the `cscse-vol` volume at `/data` in a temporary Alpine container.
2. Wrote the marker `SENSITIVE-PATIENT-RECORD` to `/data/phi.txt`.
3. Flushed pending writes with `sync`, deleted the file, and searched the mounted data path:

```bash
docker run --rm -v cscse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
   grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

### Result

The Alpine image was pulled successfully and the command completed with `scan-done`. No matching marker was printed by the file-level scan. This is not proof that deleted content is irrecoverable; it only shows that the string was not found through the files visible at that path after deletion.

**Evidence:** `TASK 6 - Data Remanence Scan.png`.

### Part B: Secure wipe

1. Created `/data/phi2.txt` containing a sensitive marker.
2. Flushed it to storage.
3. Overwrote its first 1 KiB with zeros using `dd` and `conv=notrunc`.
4. Removed the file afterwards.

```bash
docker run --rm -v cscse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
   echo wiped'
```

### Result

`dd` reported one 1 KiB record copied, followed by `wiped`. The file was overwritten before deletion.

### Security interpretation

Overwrite-before-delete can reduce residual data exposure on simple block-backed media, but it is not a universal sanitisation guarantee. Copy-on-write filesystems, snapshots, journaling, cloud storage, SSD wear levelling and encrypted volumes can retain other copies. For production systems, the preferred method is normally storage-provider sanitisation, cryptographic erasure through managed key destruction, volume lifecycle controls, and documented retention/disposal procedures.

**Evidence:** `TASK 6 - Secure Wipe Output.png`.

## 9. Overall findings

The lab shows that secure Kubernetes multi-tenancy requires defence in depth:

1. Namespaces provide the organisational base but do not automatically isolate traffic.
2. The observed HTTP 200 response demonstrates the default-open cross-tenant network risk.
3. Resource quotas constrain a tenant's share of finite cluster capacity.
4. Default-deny network policies turn the model into explicit allow-listing.
5. Namespace-scoped RBAC successfully prevented the tenant A service account from reading tenant B secrets.
6. Deleting data is not equivalent to reliably sanitising storage; the storage medium and platform behaviour determine the appropriate disposal control.

## 10. Recommendations

- Apply default-deny ingress and egress policies to every tenant namespace, then add minimal allow rules.
- Use `ResourceQuota`, `LimitRange`, and resource requests/limits for all tenant workloads.
- Bind tenant service accounts only to namespace-scoped roles with least-privilege permissions.
- Use separate storage classes, encryption keys, and retention policies for tenants with stronger isolation requirements.
- Regularly review RBAC bindings, network policies, quota usage and audit logs.
- Use platform-approved deletion and cryptographic-erasure procedures instead of relying solely on file overwriting.

## 11. Conclusion

The tasks verified core controls for running two tenants on a shared Kubernetes cluster. The evidence shows separate namespace workloads, an initially permissive network path, resource-governance controls, deny-by-default network enforcement, successful RBAC separation for secrets, and an example of safer data disposal. Together, these controls provide a practical baseline for secure multi-tenancy, provided they are continuously reviewed and supported by the underlying Kubernetes network and storage implementations.
