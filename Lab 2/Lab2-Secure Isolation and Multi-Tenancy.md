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

### Result

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
kubectl create namespace tenant-a
kubectl create namespace tenant-b

kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80

kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
```

### Screenshot

![Task 1 - Two Tenants on One Cluster](TASK%201%20-%20Two%20Tenants%20on%20One%20Cluster.png)

### Result

The result shows one running `web` pod and one `web` ClusterIP service in each namespace. Tenant A uses service IP `10.96.201.208`, while tenant B uses `10.96.153.133`. This verifies separate namespaced workloads and services on the same cluster.


## Task 2 - Default-Open Risk

### Steps performed

1. Identified the ClusterIP of the `tenant-b` web service.
2. From `tenant-a`, ran a temporary curl pod and requested the tenant B service:

```bash
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://$B_IP -o /dev/null -w 'HTTP %{http_code}\n'
```
The probe returned:
```bash
HTTP 200
```
### Screenshot

![Task 2 - Default-Open Risk](TASK%202%20-%20Default-Open%20Risk.png)

### Result

The request returned `HTTP 200`. A pod in `tenant-a` successfully reached a service in `tenant-b` before restrictive network policies were applied.


## Task 3 - Resource Quota

### Steps performed

1. Applied `tenant-a-quota` to `tenant-a`.
2. Set hard limits for five pods, one CPU core of requested CPU, and 512 MiB of requested memory.
3. Verified the quota:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

kubectl describe resourcequota tenant-a-quota -n tenant-a
```

### Screenshot

![Task 3 - Resource Quota](TASK%203%20-%20Resource%20Quota.png)

### Result

The output shows hard limits of `pods: 5`, `requests.cpu: 1`, and `requests.memory: 512Mi` for `tenant-a`. This limits tenant A's share of cluster resources and helps preserve availability for other tenants.


## Task 4 - Default-Deny Network Isolation

### Steps performed

1. Applied a default-deny `NetworkPolicy` in `tenant-a`.
2. Retested using a temporary curl probe with CPU and memory requests:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

### Screenshot

![Task 4 - Default-Deny Network Isolation](TASK%204%20-%20Default-Deny%20Network%20Isolation.png)

### Result

The probe was deleted and the command timed out waiting for its condition. This is evidence that the workload did not proceed normally after restrictive controls were introduced. A default-deny policy requires explicit allow rules for required traffic.


## Task 5 - Storage and Secret Isolation

### Steps performed

1. Used service account `system:serviceaccount:tenant-a:app-a`.
2. Checked its ability to read secrets in both namespaces:

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```
Authorization results:
```bash
yes
no
```
### Screenshot

![Task 5 - Storage and Secret Isolation](TASK%205%20-%20Storage%20and%20Secret%20Isolation.png)

### Result

The service account received `yes` for `tenant-a` and `no` for `tenant-b`. This confirms that its secret-read permission is scoped to its own tenant namespace.


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

### Result

The scan completed with `scan-done` and did not display the sensitive marker through visible files. The wipe command reported `1024 bytes (1.0KB) copied` followed by `wiped`, showing that the file was overwritten before deletion.

## Verification

```bash
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b
kubectl describe resourcequota tenant-a-quota -n tenant-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

The recorded results confirmed that both tenant namespaces had a running `web` pod and separate `web` ClusterIP services. The connection test from `tenant-a` returned `HTTP 200` before network restrictions were applied. The resource-quota output confirmed limits of five pods, one requested CPU core, and 512 MiB requested memory for `tenant-a`. After the default-deny policy task, the probe command ended with `error: timed out waiting for the condition`. RBAC verification returned `yes` for tenant A secrets and `no` for tenant B secrets. Finally, the storage test finished with `scan-done`, while the overwrite operation reported `1024 bytes (1.0KB) copied` and `wiped`.

![ResourceQuota verification](TASK%203%20-%20Resource%20Quota.png)

![Network isolation verification](TASK%204%20-%20Default-Deny%20Network%20Isolation.png)

![RBAC verification](TASK%205%20-%20Storage%20and%20Secret%20Isolation.png)

## Short Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in a multi-tenant cloud?

Namespaces separate and organise Kubernetes resources, but they do not automatically block network traffic. In this lab, the probe from `tenant-a` returned `HTTP 200` when it accessed the tenant B service. This is dangerous because a tenant workload could reach another tenant's service, enabling unauthorised access or lateral movement if no network policy is applied.

### Q2. Explain the default-deny principle and how the NetworkPolicy task implements it.

Default-deny means traffic is blocked unless an explicit policy allows it. In the lab, after the default-deny policy task, the temporary probe ended with `error: timed out waiting for the condition`. This result is consistent with restrictive network controls preventing the previously permitted communication. Required traffic must be added through specific allow policies.

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

Containers share the host operating system kernel, whereas virtual machines run separate guest operating systems with their own kernels. Therefore, a VM generally provides a stronger isolation boundary. A VM boundary should be added for highly untrusted tenants, workloads handling particularly sensitive data, or when compliance requires stronger separation than namespace, RBAC, quota, and network-policy controls can provide.

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

Data remanence is residual data that may remain after normal deletion. In this lab, the scan ended with `scan-done` and no visible `SENSITIVE` match, but that file-level result cannot prove all underlying copies were erased. Cloud users do not control every physical block, snapshot, or replica. Cryptographic erasure is preferred because destroying the encryption key makes encrypted data unreadable without requiring access to every physical copy.

### Q5. Which isolation dimension did each task exercise?

| Task | Isolation dimension demonstrated by the result |
|---|---|
| Task 1 | Compute and logical isolation through namespaces, separate pods, and separate services. |
| Task 2 | Network-isolation risk: cross-tenant HTTP access succeeded with `HTTP 200`. |
| Task 3 | Resource isolation through `ResourceQuota` limits on pods, CPU, and memory. |
| Task 4 | Network isolation through a default-deny `NetworkPolicy` enforced by Calico. |
| Task 5 | Secret and access isolation through namespace-scoped RBAC permissions. |
| Task 6 | Storage isolation and data-lifecycle protection through remanence testing and secure wipe. |

## Conclusion

This lab demonstrated that secure Kubernetes multi-tenancy needs several complementary controls. Namespaces separated the two tenants' workloads, but the `HTTP 200` result showed that namespaces alone did not isolate network traffic. `ResourceQuota` limited tenant resource consumption, Calico-enforced default-deny policies provided a safer network baseline, and RBAC prevented the tenant A service account from reading tenant B secrets. Finally, the secure-wipe task showed why deletion must be part of a wider data-lifecycle security process. Together, these controls provide a practical defence-in-depth baseline for running multiple tenants on a shared Kubernetes cluster.
