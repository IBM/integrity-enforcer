# Integrity Shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Two preparations below must be completed before installation.

1. Prepare namespace "integrity-shield-operator-system" on cluster.

2. Configure public key as secret on cluster.

As default, export public verification key to file "pubring.gpg" and create secret "keyring-secret" on cluster by the following command. (You can define any other name in CR if you want. See [doc](README_SIGNER_CONFIG.md))

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg

$ oc create secret generic --save-config keyring-secret -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

## How to protect resources with signature

Afer installing Integrity Shield on a cluster, you can protect any resources (creation and updates) on cluster with signature.

For this, the following steps must be followed.
Step 1. How to define which reource(s) should be protected
Step 2. How to check if resources are protected
Step 3. How to create a resource with signature

### Step 1. How to define which reource(s) should be protected

Create a custom resource `ResourceSigningProfile` (RSP) that defines which resource(s) should be protected, in the same namespace as resources. 

Note:  Create a namespace `secure-ns` beforehand or change it another existing namespace.

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

After creating the above RSP on cluster,  you can not create or update the resources of kind ConfigMap, Deployment and Service in `secure-ns` without valid signature.


### Step 2. How to check if resources are protected

After creating RSP as in Step 1, as an example, let's create a sample ConfigMap using the following command, which does not include any signature.

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

Let's try to create the above sample ConfigMap in `secure-ns` namespace without signature as shown below. You will see creation of sample configmap is blocked because no signature for this resource is stored in the cluster.


```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
Error from server: error when creating "/tmp/test-cm.yaml": admission webhook "ac-server.integrity-shield-operator-system.svc" denied the request: Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature. (Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"61f4aabd-df4b-4d12-90e7-11a46ee28cb0","scope":"Namespaced","userName":"IAM#cluser-user"})
```

Let's also check the generated events in the cluster:

```
$ oc get event --all-namespaces --field-selector type=IntegrityShield
NAMESPACE   LAST SEEN   TYPE              REASON         OBJECT              MESSAGE
secure-ns   40s         IntegrityShield   no-signature   configmap/test-cm   [IntegrityShieldEvent] Result: deny, Reason: "Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature.", Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"21244827-510f-484b-bbbd-4a5d262748e1","scope":"Namespaced","userName":"IAM#user-email"}

```

### Step 3. How to create a resource with signature

Now, let's create a signature for the above sample ConfigMap resource (/tmp/test-cm.yaml) using the following script (Use [yq](https://github.com/mikefarah/yq) in the script), which must be executed in the same host where the public key is setup in preparations.

```
$ curl -s https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-annotation-sign.sh | bash -s \
  signer@enterprise.com \
  /tmp/test-cm.yaml 
```

The above script would add signature, message annotations to the file `/tmp/test-cm.yaml` as shown below.


```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  annotations:
    integrityshield.io/message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29uZmlnTW...
    integrityshield.io/signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t...
data:
  key1: val1
  key2: val2
  key4: val4
```

Now, let's try creating the sample ConfigMap with signature annotation. It should be successful this time because a corresponding signature is attached in the resource file.

```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
configmap/test-cm created
```


## Supported Platforms

Integrity Shield works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design. 
We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.5 and 4.6](https://www.openshift.com/)
- [RedHat OpenShift 4.3 on IBM Cloud (ROKS)](https://www.openshift.com/products/openshift-ibm-cloud)
- [IBM Kuberenetes Service (IKS)](https://www.ibm.com/cloud/container-service/) 1.17.14
- [Minikube v1.19.1](https://kubernetes.io/docs/setup/learning-environment/minikube/)
