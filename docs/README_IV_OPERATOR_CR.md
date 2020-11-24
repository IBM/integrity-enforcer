

# Custom Resource: IntegrityVerifier

IV can be deployed with operator. You can configure IntegrityVerifier custom resource to define the configuration of IV.

## Type of Signature Verification

IV supports two modes of signature verification.
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

## Enable Helm plugin

You can enable Helm plugin to support verification of Helm provenance and integrity (https://helm.sh/docs/topics/provenance/). By enabling this, Helm package installation is verified with its provenance file.

```yaml
spec:
  verifierConfig:
    policy:
      plugin:
      - name: helm
        enabled: false
```

## Cluster signer

You can define cluster-wide signer for signing any resources on cluster.

```yaml
spec:
  verifierConfig:
    signPolicy:
      - namespaces:
        - "*"
        signers:
        - "ClusterSigner"
        - "HelmClusterSigner"
      - scope: Cluster
        signers:
        - "ClusterSigner"
        - "HelmClusterSigner"
      signers:
      - name: "ClusterSigner"
        subjects:
        - commonName: "ClusterAdmin"
      - name: "HelmClusterSigner"
        subjects:
        - email: cluster_signer@signer.com
```

## Unprocessed Requests
Some resources are not relevant to the signature-based protection by IV. The resources defined here are not processed in IV admission controller (always returns `allowed`).

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

## Install on OpenShift

When deploying OpenShift cluster, this should be set `true` (default). Then, SecurityContextConstratint (SCC) will be deployed automatically during installation. For IKS or Minikube, this should be set to `false`.

```yaml
spec:
  globalConfig:
    openShift: true
```

## IV admin

Specify user group for IV admin. The following values are default.

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
```

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

