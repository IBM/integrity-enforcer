# Security in Integrity Verifier

- Integrity Verifier uses public key specified in Integrity Verifier CR for signature verification. Public key only is deployed in cluster as Kubernetes secret, and no signing key is required on cluster.

- The following table includes the list of resources created by Integrity Verifier as default (assuming the IV is deployed on  `integrity-verifier-operator-system` namespace.) No user has direct access to resources managed by IV operator. All those resources are created/updated by IV operator according to IV CR. All pods are running in runAsNonRoot, no runAsUser, and run with `restricted` [SCC](https://docs.openshift.com/container-platform/4.6/authentication/managing-security-context-constraints.html). 



    | kind | name | namespace | owned-by |
    | ---- | ---- | ---- | ---- |
    | Deployment | integrity-verifier-operator-controller-manager | integrity-verifier-operator-system | - |
    | IntegrityVerifier | integrity-verifier-server | integrity-verifier-operator-system | - |
    | VerifierConfig | iv-config | integrity-verifier-operator-system | IV operator |
    | SignPolicy | sign-policy | integrity-verifier-operator-system | IV operator |
    | Secret | iv-server-tls | integrity-verifier-operator-system | IV operator |
    | ServiceAccount | iv-sa | integrity-verifier-operator-system | IV operator |
    | Role | iv-cluster-role-sim | integrity-verifier-operator-system | IV operator |
    | RoleBinding | iv-cluster-role-binding-sim | integrity-verifier-operator-system | IV operator |
    | Role | iv-admin-role | integrity-verifier-operator-system | IV operator |
    | RoleBinding | iv-admin-rolebinding | integrity-verifier-operator-system | IV operator |
    | PodSecurityPolicy | iv-psp | integrity-verifier-operator-system | IV operator |
    | ConfigMap | iv-rule-table-lock | integrity-verifier-operator-system | IV operator |
    | ConfigMap | iv-ignore-table-lock | integrity-verifier-operator-system | IV operator |
    | ConfigMap | iv-force-check-table-lock | integrity-verifier-operator-system | IV operator |
    | Deployment | integrity-verifier-server | integrity-verifier-operator-system | IV operator |
    | ServiceAccount | integrity-verifier-operator-manager | integrity-verifier-operator-system | - |
    | CustomResourceDefinition | integrityverifiers.apis.integrityverifier.io | (cluster scope) | - |
    | CustomResourceDefinition | verifierconfigs.apis.integrityverifier.io | (cluster scope) | IV operator |
    | CustomResourceDefinition | signpolicies.apis.integrityverifier.io | (cluster scope) | IV operator |
    | CustomResourceDefinition | resourcesignatures.apis.integrityverifier.io | (cluster scope) | IV operator |
    | CustomResourceDefinition | resourcesigningprofiles.apis.integrityverifier.io | (cluster scope) | IV operator |
    | CustomResourceDefinition | helmreleasemetadatas.apis.integrityverifier.io | (cluster scope) | IV operator |
    | ClusterRole | iv-cluster-role | (cluster scope) | IV operator |
    | ClusterRoleBinding | iv-cluster-role-binding | (cluster scope) | IV operator |
    | ClusterRole | iv-admin-clusterrole | (cluster scope) | IV operator |
    | ClusterRoleBinding | iv-admin-clusterrolebinding | (cluster scope) | IV operator |
    | ClusterRole | integrity-verifier-operator-manager-role | (cluster scope) | - |
    | ClusterRoleBinding | integrity-verifier-operator-manager-rolebinding | (cluster scope) | - |
    | WebhookConfiguration | iv-webhook-config | (cluster scope) | IV operator |

- There are two ways to setup RSPs. RSP can be deployed by specifiying RSP in Integrity Verifier CR. IV operator creates RSP in IV namespace (integrity-verifier-operator-system). RSPs is applied to the namespaces specified in targetNamespace selector in the RSP. This RSP cannot be accessed directly, but managed by IV operator. 
- User can define custom RSPs for each namespace to protect specific resources on the same namespace. User needs to put proper protection to RSP (with RBAC or with RSP itself.). The RSP in a namespace cannot be applicable to the resources on other namespace. 
- RSP can specify cluster scope resource for protection, but resource name of the protected resource must be specified explicitly.