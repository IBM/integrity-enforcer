# Integrity Shield (IShield)
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Supported Platforms

Integrity Shield works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design. 
IShield can be deployed with operator. We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.5 and 4.6](https://www.openshift.com/)
- [RedHat OpenShift 4.3 on IBM Cloud (ROKS)](https://www.openshift.com/products/openshift-ibm-cloud)
- [IBM Kuberenetes Service (IKS)](https://www.ibm.com/cloud/container-service/) 1.17.14
- [Minikube v1.19.1](https://kubernetes.io/docs/setup/learning-environment/minikube/)

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Shield on a cluster.
- A Kubernetes cluster and cluster admin access to the cluster to use `oc` or `kubectl` command

---

## Install Integrity Shield
​
This section describe the steps for deploying Integrity Shield (IShield) on your cluster. We will use RedHat OpenShift cluster and so use `oc` commands for installation. (You can use `kubectl` for Minikube or IBM Kubernetes Service.)

### Retrive the source from `integrity-enforcer` Git repository.

git clone this repository and moved to `integrity-enforcer` directory

```
$ git clone https://github.com/IBM/integrity-enforcer.git
$ cd integrity-shield
$ pwd /home/repo/integrity-enforcer
```
In this document, we clone the code in `/home/repo/integrity-enforcer`.

### Prepare namespace for installing Integrity Shield

You can deploy Integrity Shield to any namespace. In this document, we will use `integrity-shield-operator-system` to deploy Integrity Shield.
```
make create-ns

```
We switch to `integrity-shield-operator-system` namespace.
```
oc project integrity-shield-operator-system
```
All the commands are executed on the `integrity-shield-operator-system` namespace unless mentioned explicitly.

### Define public key secret in Integrity Shield

Integrity Shield requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  Integrity Shield supports X509 or PGP key for signing resources. The following steps show how you can import your signature verification key to Integrity Shield.

First, you need to export public key to a file. The following example shows a pubkey for a signer identified by an email `sample_signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export sample_signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

Then, create a secret that includes a pubkey ring for verifying signatures of resources

```
oc create secret generic --save-config keyring-secret  -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

### Define signers for each namespace


You can define signer who can provide signature for resources on each namespace. It can be configured when deploying the Integrity Shield. For that, configure signerConfig in the following Integrity Shield Custom Resource [file](../integrity-shield-operator/config/samples/apis_v1alpha1_integrityshield.yaml). Example below shows a signer `SampleSigner` identified by email `sample_signer@enterprise.com` is configured to sign rosources to be protected in any namespace and the corresponding verification key (i.e. keyring-secret) under `keyConfig`

```yaml
# Edit integrity-shield-operator/config/samples/apis_v1alpha1_integrityshield.yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: IntegrityShield
metadata:
  name: integrity-shield-server
spec:
  namespace: integrity-shield-operator-system
  shieldConfig:
    verifyType: pgp # x509
    inScopeNamespaceSelector:
      include:
      - "*"
      exclude:
      - "kube-*"
      - "openshift-*"
  signerConfig:
    policies:
    - namespaces:
      - "*"
      signers:
      - "SampleSigner"
    - scope: "Cluster"
      signers:
      - "SampleSigner"
    signers:
    - name: "SampleSigner"
      keyConfig: sample-signer-keyconfig
      subjects:
      - email: "signer@enterprise.com"
  keyConfig:
  - name: sample-signer-keyconfig
    secretName: keyring-secret


```

### Install Integrity Shield to a cluster

Integrity Shield can be installed to a cluster using a series of steps which are bundled in a script called [`install_shield.sh`](../scripts/install_shield.sh). Before executing the script `install_shield.sh`, setup local environment as follows:
- `ISHIELD_ENV <local: means that we deploy IShield to a local cluster like Minikube>`
- `ISHIELD_REPO_ROOT=<set absolute path of the root directory of cloned integrity-shield source repository`
- `KUBECONFIG=~/kube/config/minikube`  (for deploying IShield on minikube cluster)

`~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

Example:
```
$ export ISHIELD_ENV=local
$ export ISHIELD_REPO_ROOT=/home/repo/integrity-enforcer
$ export KUBECONFIG=~/kube/config/minikube
```

Prepare a private registry for hosting IShield container images, if not already exist.
The following example create a private local container image registry to host the IShield container images.

```
$ cd integrity-shield
$ make create-private-registry
```

Execute the following make commands to build Integrity Shield images.
```
$ cd integrity-shield
$ make build-images
$ make push-images-to-local
```

Then, execute the following script to deploy Integrity Shield in a cluster.

```
$ make install-crds
$ make install-operator
$ make make setup-tmp-cr
$ make create-tmp-cr
```

After successful installation, you should see two pods are running in the namespace `integrity-shield-operator-system`.

```
$ oc get pod -n integrity-shield-operator-system
integrity-shield-operator-c4699c95c-4p8wp   1/1     Running   0          5m
integrity-shield-server-85c787bf8c-h5bnj    2/2     Running   0          82m
```

---

## Protect Resources with Integrity Shield

To see how to protect resources in cluster with Integrity Shield,  please check this [doc] (https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_QUICK.md)


### Clean up Integrity Shield from the cluster

When you want to remove Integrity Shield from a cluster, run the uninstaller script [`delete_shield.sh`](../scripts/delete_shield.sh).
```
$ cd integrity-shield
$ make delete-tmp-cr
$ make delete-operator
```


