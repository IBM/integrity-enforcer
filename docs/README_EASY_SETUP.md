## Installation via CLI

This document describe steps for deploying Integrity Enforcer (IE) on your RedHat OpenShift cluster including ROKS via `oc` or `kubectl` CLI commands. 

1. git clone this repository and moved to `integrity-enforcer` directory

    ```
    git clone https://github.com/IBM/integrity-enforcer.git
    cd integrity-enforcer
    ```
    

2. Create a namespace (if not exist) and switch to ie namespace

    ```
    oc create ns integrity-enforcer-ns
    oc project integrity-enforcer-ns
    ```

 3. Setup environment
    
    - IE_ENV=local (Minikube) or IE_ENV=remote (ROKS, OpenShift) refers to the cluster
    - IE_NS=integrity-enforcer-ns refers to a namespace where IE to be deployed
    - IE_REPO_ROOT refers to root directory of the cloned `integrity-enforcer` source repository

    ```
    $ export IE_ENV=remote 
    $ export IE_NS=integrity-enforcer-ns
    $ export IE_REPO_ROOT= <root directory of `integrity-enforcer`>
    ```  

4. Setup IE secret (pubkey ring)

    IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.

    1. export key

        ```
        $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
        $ cat ~/.gnupg/pubring.gpg | base64
        ```
    2.  embed it to `keyring-secret` as follows:   

        E.g.: key-ring.yaml 
        ```
        apiVersion: v1
        kind: Secret
        metadata:
        name: keyring-secret
        type: Opaque
        data:
            pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
        ```

     3. create `keyring-secret` in namespace `IE_NS` in the cluster.
        ```
        $ oc create -f key-ring.yaml -n integrity-enforcer-ns
        ```   

5. Config `integrity-enforcer` Custom Resource file

   Edit [`deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml`](../operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml) to specify or change the following settings.

   1. signPolicy
      
   2. enforcerConfig

   3. ieAdminUserGroup (default = system:masters group)

   4. verifyType (pgp or x509)
      
      Set `spec.verifyType=pgp` when using PGP for signing resources.

6. Execute the following script to deploy `integrity-enforcer`

    ```
    ./scripts/install_enforcer.sh
    ```

7. Confirm if `integrity-enforcer` is running properly.
    
   1. Check if there are two pods running in `IE_NS`: 
      - `integrity-enforcer-operator` 
      - `integrity-enforcer-server` 
        
      ```
      $ oc get pod | grep integrity-enforcer
      integrity-enforcer-operator-c4699c95c-4p8wp   1/1     Running   0          5m
      integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
      ```

   2. Check logs of the pod: `integrity-enforcer-operator-c4699c95c-4p8wp` and confirm all IE resources are successfully created.

        ```
        $ oc logs integrity-enforcer-operator-c4699c95c-4p8wp -f
        ```

   3. Check logs of the pod: `integrity-enforcer-server-85c787bf8c-h5bnj` and confirm IE server successfully initilized.

        ```
        $ oc logs integrity-enforcer-server-85c787bf8c-h5bnj -f -c server
        ``` 

---

8. Clean up `integrity-enforcer` from a cluster
  
    Execute the following script to remove all resources related to IE deployment from cluster.
    ```
    $ cd integrity-enforcer
    $ ./scripts/delete_enforcer.sh
    ```