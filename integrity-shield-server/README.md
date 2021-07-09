## Integrity shield server

### Prerequisite
Please install OPA/Gatekeeper in the cluster.
```
$ kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.4/deploy/gatekeeper.yaml
```

### Setup
You can set up integrity shield server just by the following commands.

Please specify an image which you can push there and which can be pulled from the cluster as <YOUR_IMAGE_NAME>.

```
# Move to integrity-shield-server directory
$ pwd 
/integrity-shield/integrity-shield-server

# Generate certs and put the certs on the ./deploy/secret.yaml 
$ make gencerts

# Create namespace
$ kubectl create ns k8s-manifest-sigstore

# Build & push an image of the integrity shield server into a registry
$ make build IMG=<YOUR_IMAGE_NAME>

# Deploy the integrity shield server
$ make deploy IMG=<YOUR_IMAGE_NAME>

# Deploy a configmap for the integrity shield server
$ kubectl create -f resource/request-handler-config.yaml
```

After successful installation, you will see the following resources.
```
$ kubectl get all -n k8s-manifest-sigstore
NAME                               READY   STATUS    RESTARTS   AGE
pod/ishield-api-5b8fd4cbc6-zwtpz   1/1     Running   0          25s

NAME                           TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE
service/integrity-shield-api   ClusterIP   10.96.252.97   <none>        8123/TCP   25s

NAME                          READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/ishield-api   1/1     1            1           25s

NAME                                     DESIRED   CURRENT   READY   AGE
replicaset.apps/ishield-api-5b8fd4cbc6   1         1         1       25s
```

### Usage

To enable checking requests by integrity shield, `ConstraintTemplate` and the constraint `ManifestIntegrityConstraint` should be installed.

```
# Deploy the ConstraintTemplate
$ kubectl create -f ../gatekeeper-constraint/template-manifestintegrityconstraint.yaml

# Deploy the ManifestIntegrityConstraint
$ kubectl create -f ../gatekeeper-constraint/example/constraint-configmap.yaml
```
In this example, we use the following constraint. This constraint enforces the protection to sample-cm configmap in sample-ns.
```

apiVersion: constraints.gatekeeper.sh/v1beta1
kind: ManifestIntegrityConstraint
metadata:
  name: configmap-constraint
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["ConfigMap"] 
    namespaces:
    - "sample-ns"
  parameters:
    inScopeObjects:
    - name: sample-cm
    signers:
    - signer@signer.com
    ignoreFields:
    - objects:
      - kind: ConfigMap
      fields:
      - data.comment
```

First, creating a ConfigMap in a target namespace without signature will be blocked.
```
$ kubectl create -f sample-configmap.yaml -n sample-ns                                                                                 
Error from server ([configmap-constraint] denied; {"allow": false, "message": "no signature found"}): error when creating "sample-yaml/sample-configmap.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [configmap-constraint] denied; {"allow": false, "message": "no signature found"}
```

Then, sign the ConfigMap YAML manifest with `kubectl sigstore sign` command and creating it will pass the verification.
For more information about `k8s-manifest-sigstore`, please click [here](https://github.com/sigstore/k8s-manifest-sigstore).

```
# Attach a signature
$ export COSIGN_EXPERIMENTAL=1
$ kubectl sigstore sign -f sample-configmap.yaml -i <K8S_MANIFEST_IMAGE>
...

$ kubectl create -n sample-ns -f sample-configmap.yaml.signed
configmap/sample-cm created
```

After the above, any runtime modification without signature will be blocked.
```
$ kubectl edit cm sample-cm -n sample-ns                                                                                 
error: configmaps "sample-cm" could not be patched: admission webhook "validation.gatekeeper.sh" denied the request: [configmap-constraint] denied; {"allow": false, "message": "diff found: {\"items\":[{\"key\":\"data.key1\",\"values\":{\"after\":\"val1\",\"before\":\"val3\"}}]}"}
```
But, some parts can be changed because we define ignoreFields in the profile.
```
$ kubectl edit cm sample-cm -n sample-ns
configmap/sample-cm edited

$ kubectl get cm sample-cm -n sample-ns -o yaml

apiVersion: v1
data:
  comment: comment-changed
  key1: val1
  key2: val2
kind: ConfigMap
```
