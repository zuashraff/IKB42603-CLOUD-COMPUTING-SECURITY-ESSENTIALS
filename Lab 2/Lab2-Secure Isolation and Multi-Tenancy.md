# IKB42603 Cloud Computing Security Essentials

---

## Lab 2 - Secure Isolation & Multi-Tenancy

**Name:** Affiq  
**Student ID:** 52215124425  
**Environment:** Kali Linux, Docker Engine, kind, kubectl, and Calico

---

## Objective

This lab demonstrates secure multi-tenancy using Docker and Kubernetes. It covers compute isolation through namespaces and resource quotas, network isolation with Calico-enforced `NetworkPolicy`, storage and secret isolation using RBAC, and data remanence controls through secure deletion.

## Cluster Setup

A kind cluster named `ccse-lab2` was created with the default CNI disabled. Calico was installed because the default kind network does not enforce Kubernetes `NetworkPolicy` rules.

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

### Verification summary

The cluster was ready for policy testing after Calico completed its rollout:

```text
daemon set "calico-node" successfully rolled out
```

Calico is required because a `NetworkPolicy` has effect only when the installed CNI enforces it.

## Task 1 - Two Tenants on One Cluster

### Steps performed

1. Created or selected the `tenant-a` and `tenant-b` namespaces.
2. Deployed one web workload and a ClusterIP service in each namespace.
3. Listed the resources for both tenants:

```bash
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

### Screenshot

![Task 1 - Two Tenants on One Cluster](TASK%201%20-%20Two%20Tenants%20on%20One%20Cluster.png)

### Verification summary

The result shows one running `web` pod and one `web` ClusterIP service in each namespace. Tenant A uses service IP `10.96.201.208`, while tenant B uses `10.96.153.133`. This verifies separate namespaced workloads and services on the same cluster.

### Short question: Does a namespace alone provide complete tenant isolation?

**Answer:** No. A namespace separates scoped Kubernetes objects, but does not automatically prevent cross-tenant networking, resource exhaustion, or incorrectly granted RBAC permissions.

## Task 2 - Default-Open Risk

### Steps performed

1. Identified the ClusterIP of the `tenant-b` web service.
2. From `tenant-a`, ran a temporary curl pod and requested the tenant B service:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://$B_IP -o /dev/null -w 'HTTP %{http_code}\n'
```

### Screenshot

![Task 2 - Default-Open Risk](TASK%202%20-%20Default-Open%20Risk.png)

### Verification summary

The request returned `HTTP 200`. A pod in `tenant-a` successfully reached a service in `tenant-b` before restrictive network policies were applied.

### Short question: Why is the HTTP 200 response a security risk?

**Answer:** It proves that the tenants can communicate by default. A compromised tenant A workload could probe or access tenant B services unless network policy explicitly restricts the traffic.

## Task 3 - Resource Quota

### Steps performed

1. Applied `tenant-a-quota` to `tenant-a`.
2. Set hard limits for five pods, one CPU core of requested CPU, and 512 MiB of requested memory.
3. Verified the quota:

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

### Screenshot

![Task 3 - Resource Quota](TASK%203%20-%20Resource%20Quota.png)

### Verification summary

The output shows hard limits of `pods: 5`, `requests.cpu: 1`, and `requests.memory: 512Mi` for `tenant-a`. This limits tenant A's share of cluster resources and helps preserve availability for other tenants.

### Short question: Why is ResourceQuota important in multi-tenancy?

**Answer:** It prevents one tenant from exhausting shared compute capacity by limiting workloads and total requested CPU and memory in the namespace.

## Task 4 - Default-Deny Network Isolation

### Steps performed

1. Applied a default-deny `NetworkPolicy` in `tenant-a`.
2. Retested using a temporary curl probe with CPU and memory requests:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  --overrides='{"apiVersion":"v1","spec":{"restartPolicy":"Never","containers":[{"name":"probe","image":"curlimages/curl","resources":{"requests":{"cpu":"100m","memory":"64Mi"}}}]}}'
```

### Screenshot

![Task 4 - Default-Deny Network Isolation](TASK%204%20-%20Default-Deny%20Network%20Isolation.png)

### Verification summary

The probe was deleted and the command timed out waiting for its condition. This is evidence that the workload did not proceed normally after restrictive controls were introduced. A default-deny policy requires explicit allow rules for required traffic.

### Short question: What does a default-deny NetworkPolicy achieve?

**Answer:** It blocks traffic by default and changes the model to allow-listing: only traffic permitted by a matching policy can pass. This reduces accidental cross-tenant communication.

## Task 5 - Storage and Secret Isolation

### Steps performed

1. Used service account `system:serviceaccount:tenant-a:app-a`.
2. Checked its ability to read secrets in both namespaces:

```bash
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

### Screenshot

![Task 5 - Storage and Secret Isolation](TASK%205%20-%20Storage%20and%20Secret%20Isolation.png)

### Verification summary

The service account received `yes` for `tenant-a` and `no` for `tenant-b`. This confirms that its secret-read permission is scoped to its own tenant namespace.

### Short question: How does RBAC protect tenant secrets?

**Answer:** RBAC grants a service account only the permissions it needs. With namespace-scoped roles, tenant A's identity cannot read tenant B secrets.

## Task 6 - Data Remanence and Secure Wipe

### Steps performed

1. Mounted Docker volume `cscse-vol` at `/data`.
2. Wrote `SENSITIVE-PATIENT-RECORD` to `phi.txt`, synchronised the volume, deleted the file, and ran a file-level scan.
3. Created `phi2.txt`, overwrote it with zeros using `dd`, then deleted it.

```bash
docker run --rm -v cscse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
   grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

docker run --rm -v cscse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
   dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
   echo wiped'
```

### Screenshots

![Task 6 - Data Remanence Scan](TASK%206%20-%20Data%20Remanence%20Scan.png)

![Task 6 - Secure Wipe Output](TASK%206%20-%20Secure%20Wipe%20Output.png)

### Verification summary

The scan completed with `scan-done` and did not display the sensitive marker through visible files. The wipe command reported `1024 bytes (1.0KB) copied` followed by `wiped`, showing that the file was overwritten before deletion.

### Short question: Does deleting a file guarantee that sensitive data is gone?

**Answer:** No. Deletion normally removes the file reference rather than immediately erasing all underlying data. Overwriting may reduce exposure, but snapshots, journaling, SSD wear levelling, and cloud-storage copies can retain data. Use the storage platform's approved sanitisation or cryptographic-erasure process.

## Conclusion

This lab demonstrated that secure Kubernetes multi-tenancy needs several complementary controls. Namespaces separated the two tenants' workloads, but the `HTTP 200` result showed that namespaces alone did not isolate network traffic. `ResourceQuota` limited tenant resource consumption, Calico-enforced default-deny policies provided a safer network baseline, and RBAC prevented the tenant A service account from reading tenant B secrets. Finally, the secure-wipe task showed why deletion must be part of a wider data-lifecycle security process. Together, these controls provide a practical defence-in-depth baseline for running multiple tenants on a shared Kubernetes cluster.
