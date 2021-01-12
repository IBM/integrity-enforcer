# Integrity Shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Supported Platforms

Integrity Shield works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design. 
Integrity Shield  can be deployed with operator. We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.5 and 4.6](https://www.openshift.com/)
- [RedHat OpenShift 4.3 on IBM Cloud (ROKS)](https://www.openshift.com/products/openshift-ibm-cloud)
- [IBM Kuberenetes Service (IKS)](https://www.ibm.com/cloud/container-service/) 1.17.14
- [Minikube v1.19.1](https://kubernetes.io/docs/setup/learning-environment/minikube/)

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Shield on a cluster via OLM/OperatorHub.
- An OLM enabled Kubernetes cluster and cluster admin access to the cluster to use `oc` or `kubectl` command

---

## Install Integrity Shield
​
This section describe the steps for deploying Integrity Shield  on your cluster. We will use RedHat OpenShift cluster and so use `oc` commands for installation. (You can use `kubectl` for Minikube or IBM Kubernetes Service.)

### Retrive the source from `integrity-enforcer` Git repository.

git clone this repository and moved to `integrity-enforcer` directory

```
$ git clone https://github.com/IBM/integrity-enforcer.git
$ cd integrity-shield
$ pwd /home/repo/integrity-enforcer
```
In this document, we clone the code in `/home/repo/integrity-enforcer`.

### Prepare namespace for installing Integrity Shield in a cluster.

You can deploy Integrity Shield to any namespace. In this document, we will use `integrity-shield-operator-system` to deploy Integrity Shield.
```
oc create ns integrity-shield-operator-system

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

### Install Integrity Shield to a cluster Using OLM 

We describe the  `Integrity Shield` installation steps for an OpenShift cluster where OLM is enabled already.

Step 1. Install Integrity Shield Operator from OperatorHub in an OLM-enabled OpenShift cluster.

Select `Integrity Shield Operator` from OperatorHub and install with the following options.

- `Installed Namespace`- Select the namespace created above. We use `integrity-shield-operator-system` namespace in this documentation.
- `Approval Strategy` - Select `Automatic`
  
After successful installation, you should see a pod that is running in the namespace `integrity-shield-operator-system`.

```
$ oc get pod -n integrity-shield-operator-system
integrity-shield-operator-controller-manager-684f54655b-p227g   1/1     Running   0          5m
```

Step 2. Install Integrity Shield Server

From the list of installed operators (select `integrity-shield-operator-system` namespace), click to  `Integrity Shield Operator`.

Then click `Create IntegrityShield` and select `YAML View`

Define signers in IntegrityShield CR as below and click create.

You can define signer who can provide signature for resources on each namespace. It can be configured when deploying the Integrity Shield. For that, configure signerConfig in the following Integrity Shield Custom Resource [file](https://github.com/open-cluster-management/integrity-shield/tree/master/integrity-shield-operator/config/samples/apis_v1alpha1_integrityshield.yaml). Example below shows a signer `SampleSigner` identified by email `sample_signer@enterprise.com` is configured to sign rosources to be protected in any namespace and the corresponding verification key (i.e. keyring-secret) under `keyConfig`


```yaml
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

After successful installation, you should now see two pods are running in the namespace `integrity-shield-operator-system`.

```
$ oc get pod -n integrity-shield-operator-system
integrity-shield-operator-c4699c95c-4p8wp   1/1     Running   0          5m
integrity-shield-server-85c787bf8c-h5bnj    2/2     Running   0          82m
```

---

## Protect Resources with Integrity Shield

To see how to protect resources in cluster with Integrity Shield,  please check this [doc](https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_QUICK.md)


For additional configuration options, samples and more information on using the operator, consult the [Integrity Shield documentation](https://github.com/open-cluster-management/integrity-shield/tree/master/docs).

