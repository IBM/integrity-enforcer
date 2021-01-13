# Integrity Shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Requirements

### Prepare namespace for installing Integrity Shield in a cluster.

You can deploy Integrity Shield to any namespace. In this document, we will use `integrity-shield-operator-system` to deploy Integrity Shield.
```
oc create ns integrity-shield-operator-system
```

### Define public key secret in Integrity Shield

Integrity Shield requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected. 

Export public key to a file as shown below. 

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

Then, create a secret that includes a pubkey ring for verifying signatures of resources

```
oc create secret generic --save-config keyring-secret  -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

## Install Integrity Shield

Install `Integrity Shield` Operator and Server (`Custom Resource`) from OperatorHub.

## Protect Resources with Integrity Shield

Once Integrity Shield is deployed to a cluster, you are ready to put resources on the cluster into signature-based protection.


To start actual protection, you need to define which resources should be protected specifically. This section describes the execution flow for protecting a specific resource (e.g. ConfigMap) in a specific namespace (e.g. secure-ns) on your cluster.

The steps for protecting resources include:

The steps for protecting resources include:
- Define which reource(s) should be protected.
- Create a resource with signature.

### Define which reource(s) should be protected

You can define which resources should be protected with signature in a cluster by Integrity Shield. A custom resource `ResourceSigningProfile` (RSP) includes the definition and it is created in the same namespace as resources. Example below illustrates how to define RSP to protect three resources ConfigMap, Deployment, and Service in a namespace `secure-ns`. After this, any resources specified here cannot be created/updated without valid signature.

```
$ cat <<EOF | oc apply -n secure-ns -f -
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSigningProfile
metadata:
  name: sample-rsp
spec:
  protectRules:
  - match:
    - kind: ConfigMap
    - kind: Deployment
    - kind: Service
EOF

resourcesigningprofile.apis.integrityshield.io/sample-rsp created
```

See [Define Protected Resources](https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_FOR_RESOURCE_SIGNING_PROFILE.md) for detail specs.


### Create a resource with signature

Any configmap cannot be created without signature in `secure-ns` namespace. Run the following command to create a sample configmap.

```
cat << EOF > /tmp/test-cm.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key1: val1
  key2: val2
  key4: val4
EOF
```


run the command below for trying to create the configmap in `secure-ns` namespace without signature. You will see it is blocked because no signature for this resource is stored in the cluster.


```
$ oc apply -f /tmp/test-cm.yaml -n secure-ns
Error from server: error when creating "test-cm.yaml": admission webhook "ac-server.integrity-shield-operator-system.svc" denied the request: No signature found
```

Run the following script to generate a signature (Use [yq](https://github.com/mikefarah/yq) in the script)

```
$ curl -s https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-rs-sign.sh | bash -s \
  signer@enterprise.com \
  /tmp/test-cm.yaml \
  /tmp/test-cm-rs.yaml
```

Then, output file `/tmp/test-cm-rs.yaml` is A custom resource `ResourceSignature` which includes signature of the input yaml.


```yaml
apiVersion: apis.integrityshield.io/v1alpha1
kind: ResourceSignature
metadata:
  annotations:
    integrityshield.io/messageScope: spec
    integrityshield.io/signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t
  name: rsig-configmap-test-cm
  labels:
    integrityshield.io/sigobject-apiversion: v1
    integrityshield.io/sigobject-kind: ConfigMap
    integrityshield.io/sigtime: "1610442484"
spec:
  data:
    - message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29u
      signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t
      type: resource
```


Create this resource.
```
$ oc create -f /tmp/test-cm-rs.yaml -n secure-ns
resourcesignature.apis.integrityshield.io/rsig-configmap-test-cm created
```


Then, run the same command again to create ConfigMap. It should be successful this time because a corresponding ResourceSignature is available in the cluster.

```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm created
```


For detail configuration, consult the [Integrity Shield documentation](https://github.com/open-cluster-management/integrity-shield/tree/master/docs).


## Supported Platforms

Integrity Shield works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design. 
Integrity Shield  can be deployed with operator. We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.5 and 4.6](https://www.openshift.com/)
- [RedHat OpenShift 4.3 on IBM Cloud (ROKS)](https://www.openshift.com/products/openshift-ibm-cloud)
- [IBM Kuberenetes Service (IKS)](https://www.ibm.com/cloud/container-service/) 1.17.14
- [Minikube v1.19.1](https://kubernetes.io/docs/setup/learning-environment/minikube/)
