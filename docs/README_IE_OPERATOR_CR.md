

# Custom Resource: IntegrityEnforcer

IE can be deployed with operator. You can configure IntegrityEnforcer custom resource to define the configuration of IE.

## Type of Signature Verification

IE supports two modes of signature verification.
- `pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing. certificate is not used.
- `x509`: use signing key with X509 public key certificate.

`spec.verifyType` should be set either `pgp` (default) or `x509`.

```yaml
apiVersion: research.ibm.com/v1alpha1
kind: IntegrityEnforcer
metadata:
  name: integrity-enforcer-server
spec:
  enforcerConfig:
    verifyType: pgp
```

## Enable Helm plugin

You can enable Helm plugin to support verification of Helm provenance and integrity (https://helm.sh/docs/topics/provenance/). By enabling this, Helm package installation is verified with its provenance file.

```yaml
spec:
  enforcerConfig:
    policy:
      plugin:
      - name: helm
        enabled: false
```

## Cluster signer

You can define cluster-wide signer for signing any resources on cluster.

```yaml
spec:
  enforcerConfig:
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
Some resources are not relevant to the signature-based protection by IE. The resources defined here are not processed in IE admission controller (always returns `allowed`).

```yaml
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

## IE Run mode
You can set run mode. Two modes are available. `enforce` mode is default. `detect` mode always allows any admission request, but signature verification is conducted and logged for all protected resources. `enforce` is set unless specified.

```yaml
spec:
  enforcerConfig:
    mode: "detect"
```

## Install on OpenShift

When deploying OpenShift cluster, this should be set `true` (default). Then, SecurityContextConstratint (SCC) will be deployed automatically during installation. For IKS or Minikube, this should be set to `false`.

```yaml
spec:
  globalConfig:
    openShift: true
```

## IE admin

Specify user group for IE admin. The following values are default.

```yaml
spec:
  enforcerConfig:
    ieAdminUserGroup: "system:masters,system:cluster-admins"
```

Also, you can define IE admin role. This role will be created automatically during installation when `autoIEAdminRoleCreationDisabled` is `false` (default).

```yaml
spec
  security
    ieAdminSubjects:
      - apiGroup: rbac.authorization.k8s.io
        kind: Group
        name: system:masters
    autoIEAdminRoleCreationDisabled: false
```


## Webhook configuration

You can specify webhook filter configuration for processing requests in IE. As default, all requests for namespaced resources and selected cluster-scope resources are forwarded to IE. If you want to protect a resource by IE, it must be covered with this filter condition.

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
    - clusterresourcesigningprofiles
```

## Logging

Console log includes stdout logging from IE server. Context log includes admission control results. Both are enabled as default. You can specify namespaces in scope. `'*'` is wildcard. `'-'` is empty stiring, which implies cluster-scope resource.
```yaml
spec:
  enforcerConfig:
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

