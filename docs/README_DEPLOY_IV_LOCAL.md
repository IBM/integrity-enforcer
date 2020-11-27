## Install IV to a local cluster (minikube)

This section describe the steps for deploying Integrity Verifier (IV) on your local minikube cluster via `oc` or `kubectl` CLI commands. 

1. Retrive the source from `integrity-enforcer` Git repository.

    git clone this repository and moved to `integrity-enforcer` directory

    ```
    $ git clone https://github.com/IBM/integrity-enforcer.git
    $ cd integrity-verifier
    $ pwd /home/repo/integrity-enforcer
    ```
    In this document, we clone the code in `/home/repo/integrity-enforcer`.
    
2.  Prepare a namespace to deploy Integrity Verifier. 

    The following command uses `integrity-verifier-operator-system` as default namespace for Integrity Verifier. 
    ```
    make create-ns
    ```
    We swtich to `integrity-verifier-operator-system` namespace.
    ```
    oc project integrity-verifier-operator-system
    ```
    
3. Define a public key secret for verifying signature by Integrity Verifier.

    Integrity Verifier requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  Integrity Verifier supports X509 or PGP key for signing resources.

    By default, Integrity Verifier provides a key setup. 
    
    If you would like to use default key setup, the following command creates a public key secret for verifying signature
    ```
    make create-key-ring
    ```

    If you would like to use your own key, please follow the steps:

    1. If you do not have a PGP key, generate PGP key as follows.
   
        Use your `name` and `email` to generate PGP key using the following command
        ```
        $ gpg --full-generate-key
        ```

        Confirm if key is avaialble in keyring. The following example shows a PGP key is successfully generated using email `signer@enterprise.com`
        ```
        $ gpg -k signer@enterprise.com
        gpg: checking the trustdb
        gpg: marginals needed: 3  completes needed: 1  trust model: pgp
        gpg: depth: 0  valid:   2  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 2u
        pub   rsa3072 2020-09-24 [SC]
              FE866F3F88FCDAF42BB1B1ED23EC90D3DAD9A6C0
        uid           [ultimate] signer@enterprise.com <signer@enterprise.com>
        sub   rsa3072 2020-09-24 [E]
        ```

    2. Once you have a PGP key, export it as follows.

        The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `~/.gnupg/pubring.gpg`.

        ```
        $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
        ```

    3.  Define a secret that includes a pubkey ring for verifying signatures of resources
        
        The encoded content of `~/.gnupg/pubring.gpg` can be retrived by using the following command:

        ```
        $ cat ~/.gnupg/pubring.gpg | base64
        ```

        Once you have the encoded content of `~/.gnupg/pubring.gpg`, embed it to `/tmp/keyring-secret.yaml` as follows.

            ```yaml
            apiVersion: v1
            kind: Secret
            metadata:
              name: keyring-secret
              type: Opaque
            data:
              pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
            ```

    4.  Create `keyring-secret` in a namespace ``integrity-verifier-operator-system`` in the cluster.

        ```
        $ oc create -f  /tmp/keyring-secret.yaml -n `integrity-verifier-operator-system`
        ```

4. Define which signers (identified by email) should sign the resources in a specific namespace.

    If you use default key setup, the following command setup signers. 
    ```
    make setup-tmp-cr
    ```

    If you use your own key setup, configure signPolicy in the following `integrity-verifier` Custom Resource file:

    Edit [`config/samples/apis_v1alpha1_integrityverifier.yaml`](../integrity-verifier-operator/config/samples/apis_v1alpha1_integrityverifier.yaml) to specify a signer for a namespace `secure-ns`.

    Example below shows a signer `SampleSigner` identified by email `signer@enterprise.com` is configured to sign rosources to be protected in any namespace.

    ```yaml
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
        - email: "signer@enterprise.com"
    ```


5. Install Integrit Verifier to a cluster

    Integrity Verifier can be installed to cluster using a series of steps which are bundled in make commands.
    
    Before execute the make command, setup local environment as follows:
    - `IV_REPO_ROOT=<set absolute path of the root directory of cloned integrity-verifier source repository>`
    - `KUBECONFIG=~/kube/config/minikube`  (for deploying IV on minikube cluster)

    `~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

    The following example shows how to set up a local envionement.  

    ```
    $ export KUBECONFIG=~/kube/config/minikube
    $ export IV_REPO_ROOT=/home/gajan/go/src/github.com/IBM/integrity-enforcer      
    ``` 

    Execute the following make commands to build Integrity Verifier images.
    ```
    $ cd integrity-verifier
    $ make build-images
    $ make tag-images-to-local
    ```

    Execute the following make commands to deploy Integrity Verifier in a cluster.

    ```
    $ make install-crds
    $ make install-operator
    ```

    If you use default key setup, the following command create Integrity Verifier CR in cluster. 
    ```
    $ make create-tmp-cr
    ```

    If you use your own key setup, the following command create Integrity Verifier CR in cluster. 
    ```
    $ make create-cr
    ```

6. Confirm if `integrity-verifier` is running successfully in a cluster.
    
    Check if there are two pods running in the namespace `integrity-verifier-operator-system`: 
        
    ```
    $ oc get pod -n integrity-verifier-operator-system
    integrity-verifier-operator-c4699c95c-4p8wp   1/1     Running   0          5m
    integrity-verifier-server-85c787bf8c-h5bnj    2/2     Running   0          82m
    ```

7. Clean up `integrity-verifier` from a cluster

    Execute the following script to remove all resources related to IV deployment from cluster.
    ```
    $ cd integrity-verifier
    $ make delete-tmp-cr
    $ make delete-operator
    ```