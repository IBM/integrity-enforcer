## How `Integrity Enforcer` works

1. Protect resource(s) specified in a ResourceProtectionProfile
    E.g.:  The following snippet shows an example ResourceProtectionProfile.  In this example,  ResourceProtectionProfile defines that resources such as ConfigMap, Depoloyment, and Service in a namespace `secure-ns' should be protected by IE.

    ```
    apiVersion: research.ibm.com/v1alpha1
    kind: ResourceProtectionProfile
    metadata:
    name: sample-rpp
    spec:
    rules:
    - match:
        - namespace: secure-ns
          kind: ConfigMap
        - namespace: secure-ns
          kind: Deployment
        - namespace: secure-ns
          kind: Service
    ```
   
2. Integrity Enforcer (IE)

    1. IE is implmented as an admission controller, specifically as a MutatingAdmissionWebhook in a Kubernetes cluster.

    2. IE enables signature based configuration drift prevention based on a Mutation Admission Webhook in a Kubernetes cluster.

    3. IE is installed on a specific namespace (e.g. IE_NS=integrity-enforcer-ns) in a cluster

    4. IE includes the following configurations (IE resources) to enable protecting resources

        - SignPolicy (sp)
        - ResourceSignature (rs)
        - ResourceProtectionProfile (rpp)
        - ClusterResourceProtectionProfile (crpp)
    5. Allow/block creating/updating resources with annotation or rpp.status, events

3. Integrity Enforcer is managed by ie-admin (full control on IE resources such as sp, rs, rpp, crpp )