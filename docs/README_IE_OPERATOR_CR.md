

## Custom Resource: IntegrityEnforcer 

IE can be deployed with operator. You can configure IntegrityEnforcer custom resource to define the configuration of IE. 

### Type of Signature Verification

IE supports two modes of signature verification. 
- `pgp`: use [gpg key]((https://www.gnupg.org/index.html)) for signing. certificate is not used. 
- `x509`: use signing key with X509 public key certificate. 

`spec.verifyType` should be set either `pgp` (default) or `x509`.
```
apiVersion: research.ibm.com/v1alpha1
kind: IntegrityEnforcer
metadata:
  name: integrity-enforcer-server
spec:
  verifyType: pgp
```

### Enable Helm plugin

You can enable Helm plugin to support verification of Helm provenance and integrity (https://helm.sh/docs/topics/provenance/). By enabling this, Helm package installation is verified with its provenance file. 

package signature ()

```
spec:
  enforcerConfig:
    policy:
      plugin:
      - name: helm
      enabled: false
```

### Cluster signer 

for resources and helm resources
```
spec:
  enforcerConfig:
    signPolicy:
      signers:
      - name: "ClusterSigner"
        subjects:
        - commonName: "ClusterAdmin"
      - name: "HelmClusterSigner"
        subjects:
        - email: cluster_signer@signer.com
```


### Unprocessed Requests
define which resouces in admission requests should not be processed in IE. 
```
spec:
  enforcerConfig:
    ignore:
    - kind: Event
    - kind: Lease
    - kind: Endpoints
    - kind: TokenReview
    - kind: SubjectAccessReview
    - kind: SelfSubjectAccessReview
```

### IE Run mode
mode = enforce or detect
```
spec:
  enforcerConfig:
    mode: "detect"
```

### Install on OpenShift

enable auto deploy scc
```
spec:
  globalConfig:
    openShift: true
```

### Signature Verification Key

```
spec:
  certPoolConfig:
    createIfNotExist: false
    keyValue: test
    name: ie-certpool-secret
  keyRingConfig:
    createIfNotExist: false
    keyValue: test
    name: keyring-secret
```

### IE admin

IE Admin users
```
spec:
  enforcerConfig:
    ieAdminUserGroup: "system:masters"
```

IE Admin role
```
spec
  security
    ieAdminSubjects:
      - apiGroup: rbac.authorization.k8s.io
        kind: Group
        name: system:masters
    autoIEAdminRoleCreationDisabled: false
```


### Webhook configuration

```
spec
  webhookNamespacedResource:
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: ["*"]
  webhookClusterResource:
    apiGroups: ["*"]
    apiVersions: ["*"]
    resources: 
    - podsecuritypolicies
    - clusterrolebindings
    - clusterroles
    - clusterresourceprotectionprofiles
```

## Logging


### logging scope

### server log

### forwarder log
