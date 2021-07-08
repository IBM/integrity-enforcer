# integrity-shield
Integrity Shield is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.


## integrity shield server
Integrity shield server includes main logic to verify admission request.  
Integrity shield server uses [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) internally to verify k8s manifest.

## gatekeeper constraint
Integrity shield can work with OPA/Gatekeeper by installing ConstraintTemplate(`template-manifestintegrityconstraint.yaml` ).

## admission controller
This is an admission controller for verifying k8s manifest with sigstore signing. You can use this admission controller instead of OPA/Gatekeeper.