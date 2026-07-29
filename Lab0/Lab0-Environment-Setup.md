# Lab 0 - Environment Setup

## Objective

Prepare and validate a local cloud-native lab environment using Docker, the AWS CLI, OpenSSL, LocalStack, and a Kubernetes-in-Docker (`kind`) cluster.

## Evidence reviewed

The evidence folder contains eight screenshots (`1.png` to `8.png`). They demonstrate that every required component was available and working at the time of validation.

| Requirement | Validation performed | Result |
| --- | --- | --- |
| Docker | `docker --version` | Docker `28.5.2` installed |
| Docker engine | `sudo docker run hello-world` | Image downloaded and container completed successfully |
| AWS CLI | `aws --version` | AWS CLI `2.36.9` installed |
| Kubernetes tools | `kind --version` and `kubectl version --client` | kind `0.23.0`; kubectl client `v1.33.4` |
| OpenSSL | `openssl version` and `oathtool --version` | OpenSSL `3.6.2`; oathtool `2.6.14` |
| LocalStack | `curl http://localhost:4566/_localstack/health` | Services reported as available; LocalStack `3.0.2` Community |
| Kubernetes cluster | `kubectl cluster-info --context kind-ccse` and `kubectl get nodes` | Control plane and CoreDNS running; node `ccse-control-plane` Ready |
| Local AWS identity | `aws --endpoint-url=$EP sts get-caller-identity` | Local test identity returned successfully |

## Step-by-step setup and validation

### 1. Verify Docker

Run the following command:

```bash
docker --version
```

Expected result: Docker prints its installed version. The captured evidence shows version `28.5.2`.

Then confirm that the Docker daemon can run a container:

```bash
sudo docker run hello-world
```

Expected result: the command prints `Hello from Docker!` and confirms that the installation appears to be working correctly. The evidence shows that the image was pulled and the test container ran successfully.

### 2. Verify the AWS CLI

Run:

```bash
aws --version
```

Expected result: an AWS CLI version string. The supplied evidence records `aws-cli/2.36.9` on Kali Linux.

### 3. Verify Kubernetes tooling

Check the local Kubernetes tools:

```bash
kind --version
kubectl version --client
```

Expected result: both commands return version information. The evidence confirms kind `0.23.0` and a kubectl client version of `v1.33.4` with Kustomize `v5.5.0`.

### 4. Verify cryptographic utilities

Run:

```bash
openssl version
oathtool --version
```

Expected result: both commands display installed versions. The evidence confirms OpenSSL `3.6.2` and oathtool `2.6.14`.

### 5. Verify LocalStack

Query the LocalStack health endpoint:

```bash
curl http://localhost:4566/_localstack/health
```

Expected result: a JSON document showing the LocalStack services as `available`. The submitted result reports the available state for services including IAM, S3, Lambda, DynamoDB, CloudWatch, SQS, SNS, STS, and more; it identifies the installation as LocalStack Community `3.0.2`.

### 6. Verify the kind Kubernetes cluster

Confirm cluster connectivity and node health:

```bash
kubectl cluster-info --context kind-ccse
kubectl get nodes
```

Expected result: Kubernetes control-plane and CoreDNS endpoints are shown, and the cluster node is in the `Ready` state. The evidence shows `ccse-control-plane` as `Ready`, role `control-plane`, Kubernetes version `v1.30.0`.

### 7. Verify AWS access through LocalStack

Set the LocalStack endpoint in the current shell, then query the security-token service:

```bash
EP=http://localhost:4566
aws --endpoint-url="$EP" sts get-caller-identity
```

Expected result: a JSON identity response. The evidence shows the expected LocalStack test identity: account `000000000000`, user ID `AKIAIOSFODNN7EXAMPLE`, and the corresponding root ARN.

## Conclusion

All environment checks in the supplied evidence passed. Docker can run containers, LocalStack is healthy, the `kind-ccse` Kubernetes cluster is operational, and AWS CLI calls reach LocalStack successfully. The Lab 0 environment is ready for subsequent exercises.
