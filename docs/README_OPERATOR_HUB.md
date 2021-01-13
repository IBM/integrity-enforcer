# Integrity Shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

Integrity Shield's capabilities are

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Prerequisites

### Prepare namespace for installing Integrity Shield in a cluster.

You can deploy Integrity Shield to any namespace. For instance, create a namespace `integrity-shield-operator-system` in cluster to deploy Integrity Shield.

### Define public key secret in Integrity Shield

Integrity Shield requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected. 

You coud export a public key to a file as shown below. 

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

Then, you can create a secret that includes a pubkey ring for verifying signatures of resources in the cluster with the following command.

```
oc create secret generic --save-config keyring-secret  -n integrity-shield-operator-system --from-file=/tmp/pubring.gpg
```

## Protect Resources with Integrity Shield

Once Integrity Shield is deployed to a cluster, you are ready to put resources on the cluster into signature-based protection.

### Define which reource(s) should be protected

You can define which resources should be protected with signature in a cluster by Integrity Shield. 

A custom resource `ResourceSigningProfile` (RSP) includes the definition and it is created in the same namespace as resources. 

Example below illustrates how to define a RSP to protect three resources ConfigMap, Deployment, and Service in a namespace `secure-ns`. 

After creating below RSP in cluster, the resources of kind ConfigMap, Deployment and Service in `secure-ns` cannot be created/updated without valid signature.

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

See [Define Protected Resources](https://github.com/open-cluster-management/integrity-shield/blob/master/docs/README_FOR_RESOURCE_SIGNING_PROFILE.md) for detail specs.


### Create a resource with signature

You cannot create a configmap without signature in `secure-ns` namespace. 

Let's create a sample ConfigMap using the following command, which does not include any signature.

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

Let's try to create the above sample ConfigMap in `secure-ns` namespace without signature as shown below. You will see Integrity Shield blocked it because no signature for this resource is stored in the cluster.


```
$ oc create -f /tmp/test-cm.yaml -n secure-ns
Error from server: error when creating "/tmp/test-cm.yaml": admission webhook "ac-server.integrity-shield-operator-system.svc" denied the request: Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature. (Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"61f4aabd-df4b-4d12-90e7-11a46ee28cb0","scope":"Namespaced","userName":"IAM#cluser-user"})
```

Let's also check the Integrity Shield block events as follows:

```
$ oc get event --all-namespaces --field-selector type=IntegrityShield
NAMESPACE   LAST SEEN   TYPE              REASON         OBJECT              MESSAGE
secure-ns   40s         IntegrityShield   no-signature   configmap/test-cm   [IntegrityShieldEvent] Result: deny, Reason: "Signature verification is required for this request, but no signature is found. Please attach a valid signature to the annotation or by a ResourceSignature.", Request: {"kind":"ConfigMap","name":"test-cm","namespace":"secure-ns","operation":"CREATE","request.uid":"21244827-510f-484b-bbbd-4a5d262748e1","scope":"Namespaced","userName":"IAM#user-email"}

```
Now, let's create a signature for the above sample ConfigMap resource (/tmp/test-cm.yaml) using the following script (Use [yq](https://github.com/mikefarah/yq) in the script)

```
$ curl -s https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-annotation-sign.sh | bash -s \
  signer@enterprise.com \
  /tmp/test-cm.yaml 
```

Then, the above script would add signature, message annotations to the file `/tmp/test-cm.yaml` as shown below.


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


For detail understanding, consult the [Integrity Shield documentation](https://github.com/open-cluster-management/integrity-shield/tree/master/docs).


## Supported Platforms

Integrity Shield works as Kubernetes Admission Controller using Mutating Admission Webhook, and it can run on any Kubernetes cluster by design. 
We have verified the feasibility on the following platforms:

- [RedHat OpenShift 4.5 and 4.6](https://www.openshift.com/)
- [RedHat OpenShift 4.3 on IBM Cloud (ROKS)](https://www.openshift.com/products/openshift-ibm-cloud)
- [IBM Kuberenetes Service (IKS)](https://www.ibm.com/cloud/container-service/) 1.17.14
- [Minikube v1.19.1](https://kubernetes.io/docs/setup/learning-environment/minikube/)
