

# Custom Resource: IntegrityVerifier

Integrity Verifier can be deployed with operator. You can configure IntegrityVerifier custom resource to define the configuration of IV.

## Type of Signature Verification

Integrity Verifier supports two modes of signature verification.
- `pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing. certificate is not used.
- `x509`: use signing key with X509 public key certificate.

`spec.verifyType` should be set either `pgp` (default) or `x509`.

```yaml
apiVersion: apis.integrityverifier.io/v1alpha1
kind: IntegrityVerifier
metadata:
  name: integrity-verifier-server
spec:
  verifierConfig:
    verifyType: pgp
```

<!-- ## Enable Helm plugin

You can enable Helm plugin to support verification of Helm provenance and integrity (https://helm.sh/docs/topics/provenance/). By enabling this, Helm package installation is verified with its provenance file.

```yaml
spec:
  verifierConfig:
    policy:
      plugin:
      - name: helm
        enabled: false
``` -->

## Verification Key and Sign Policy Configuration

The list of verification key names should be set as `keyRingConfigs` in this CR.
The operator will start installing Integrity Verifier when all key secrets listed here are ready.

Also, you can set SignPolicy here.
This policy defines signers that are allowed to create/update resources with their signature in some namespaces.
(see [How to configure SignPolicy](README_CONFIG_SIGNER_POLICY.md) for detail.)

```yaml
spec:
  keyRingConfigs:
  - name: keyring-secret
  signPolicy:
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
      secret: keyring-secret
      subjects:
      - email: "sample_signer@signer.com"
```

## Resource Signing Profile Configuration
You can define one or more ResourceSigningProfiles that are installed by this operator.
This configuration is not set by default.
(see [How to configure ResourceSigningProfile](README_FOR_RESOURCE_PROTECTION_PROFILE.md) for detail.)

```yaml
spec:
  resourceSigningProfiles:
  - name: sample-rsp
    targetNamespaceSelector:
      include:
      - "secure-ns"
    protectRules:
    - match:
      - kind: "ConfigMap"
        name: "*"
```

## Define In-scope Namespaces
You can define which namespace is not checked by Integrity Verifier even if ResourceSigningProfile is there.
Wildcard "*" can be used for this config. By default, Integrity Verifier checks RSPs in all namespaces except ones in `kube-*` and `openshift-*` namespaces.

```yaml
spec:
  inScopeNamespaceSelector:
    include:
    - "*"
    exclude:
    - "kube-*"
    - "openshift-*"
```

## Unprocessed Requests
Some resources are not relevant to the signature-based protection by Integrity Verifier.
The resources defined here are not processed in IV admission controller (always returns `allowed`).

```yaml
spec:
  verifierConfig:
    ignore:
    - kind: Event
    - kind: Lease
    - kind: Endpoints
    - kind: TokenReview
    - kind: SubjectAccessReview
    - kind: SelfSubjectAccessReview
```

## IV Run mode
You can set run mode. Two modes are available. `enforce` mode is default. `detect` mode always allows any admission request, but signature verification is conducted and logged for all protected resources. `enforce` is set unless specified.

```yaml
spec:
  verifierConfig:
    mode: "detect"
```

<!-- ## Install on OpenShift

When deploying OpenShift cluster, this should be set `true` (default). Then, SecurityContextConstratint (SCC) will be deployed automatically during installation. For IKS or Minikube, this should be set to `false`.

```yaml
spec:
  globalConfig:
    openShift: true
``` -->

## IV admin

Specify user group for IV admin with comma separated strings like the following. This value is empty by default.

```yaml
spec:
  verifierConfig:
    ivAdminUserGroup: "system:masters,system:cluster-admins"
```

Also, you can define IV admin role. This role will be created automatically during installation when `autoIVAdminRoleCreationDisabled` is `false` (default).

```yaml
spec
  security
    ivAdminSubjects:
      - apiGroup: rbac.authorization.k8s.io
        kind: Group
        name: system:masters
    autoIVAdminRoleCreationDisabled: false
```

<!-- 
## Webhook configuration

You can specify webhook filter configuration for processing requests in IV. As default, all requests for namespaced resources and selected cluster-scope resources are forwarded to IV. If you want to protect a resource by IV, it must be covered with this filter condition.

```yaml
spec:
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
``` -->

## Logging

Console log includes stdout logging from IV server. Context log includes admission control results. Both are enabled as default. You can specify namespaces in scope. `'*'` is wildcard. `'-'` is empty stiring, which implies cluster-scope resource.
```yaml
spec:
  verifierConfig:
    log:
      consoleLog:
        enabled: true
        inScope:
        - namespace: '*'
        - namespace: '-'
      contextLog:
        enabled: true
        inScope:
        - namespace: '*'
        - namespace: '-'
      logLevel: info
```

