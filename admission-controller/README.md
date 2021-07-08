# k8s admission controller for k8s manifest verification

This is an admission controller for verifying k8s manifest with sigstore signing.
You can use this admission controller instead of OPA/Gatekeeper.

## Manifest integrity profile

By installing a resource `ManifestIntegrityProfile`, you can enable the verification by integrity shield.  
This is an example of `ManifestIntegrityProfile` to protect ConfigMap in sample-ns.

```
apiVersion: apis.integrityshield.io/v1alpha1
kind: ManifestIntegrityProfile
metadata:
  name: constraint-configmap
spec:
  match:
    kinds:
    - kinds:
      - ConfigMap
    namespaces:
    - sample-ns
  parameters:
    ignoreFields:
    - fields:
      - data.comment
      objects:
      - kind: ConfigMap
    signers:
    - signer@signer.com
```
