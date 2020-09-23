
## Configure Sign Policy

1. Get the sign policy (after IE is successfully deplyoed in namespace `integrity-enforcer-ns`)
   
   ```
   $ oc get signpolicies.research.ibm.com signer-policy -n integrity-enforcer-ns -o yaml > /tmp/sign-policy.yaml
   ```
2.  Configure the sign policy by adding the following snipet to `/tmp/sign-policy.yaml`
    
    Example below shows a signer `service-a` identified by email `signer@enterprise.com` is configured to sign rosources to be created in namespace `secure-ns`.
    
    ```
        -------
        spec:
          policy:
            policies:
            - namespaces:
              - secure-ns
              signers:
              - service-a
            signers:
            - name: service-a
              subjects:
              - email: signer@enterprise.com
        -------
    ```

    ```
    $ oc apply -f /tmp/sign-policy.yaml -n integrity-enforcer-ns
    signpolicy.research.ibm.com/signer-policy configured
    ```

    E.g. Final sign policy
    ```
        apiVersion: research.ibm.com/v1alpha1
        kind: SignPolicy
        metadata:
        creationTimestamp: "2020-09-23T00:32:46Z"
        generation: 2
        name: signer-policy
        namespace: integrity-enforcer-ns
        ownerReferences:
        - apiVersion: research.ibm.com/v1alpha1
            blockOwnerDeletion: true
            controller: true
            kind: IntegrityEnforcer
            name: integrity-enforcer-server
            uid: 3d2963b4-2ff1-4ce3-af8b-1215efffc9a7
        resourceVersion: "8140367"
        selfLink: /apis/research.ibm.com/v1alpha1/namespaces/integrity-enforcer-ns/signpolicies/signer-policy
        uid: b4ecfe1b-af48-49ae-8ac9-5cff0304b46f
        spec:
            policy:
                policies:
                - namespaces:
                  - secure-ns
                  signers:
                  - service-a
                signers:
                - name: service-a
                  subjects:
                  - email: signer@enterprise.com
        status: {}  
    ```