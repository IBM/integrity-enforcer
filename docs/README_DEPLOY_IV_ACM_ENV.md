
# How to install Integrity Verifier using the ACM policy

## 

This section describe the steps for deploying Integrity Verifier (IV) on your managed cluster via ACM policy.

1. Retrive the source from `policy-collection` Git repository.

    git clone this repository and moved to `policy-collection` directory

    ```
    $ git clone https://github.com/open-cluster-management/policy-collection.git
    $ cd policy-collection
    $ pwd /home/repo/policy-collection
    ```
    In this document, we clone the code in `/home/repo/policy-collection`.
    
  
2. Setup a verification key in a managed cluster(s).

   Refer this document to for propagating a verification key from an ACM hub cluster to a managed cluster.

      
4.  Prepare a namespace to deploy Policies in a ACM hub cluster. 

    The following command uses `policies` as default namespace for creating policies in a ACM hub cluster. 
    ```
    oc create ns polices 
    
    ```
    We switch to `polices` namespace.
    ```
    oc project polices
    ```        
   
5. Sign policies
    
   1. Signing key Type
    `pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing.
   
   2. GPG Key Setup
    First, you need to setup GPG key/

    If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

    The following example shows how to generate GNUPG key (with your email address e.g. signer@enterprise.com)

    ```
    gpg --full-generate-key

    ```

    Confirm if key is avaialble in keyring

    ```
    gpg -k signer@enterprise.com
    gpg: checking the trustdb
    gpg: marginals needed: 3  completes needed: 1  trust model: pgp
    gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
    pub   rsa2048 2020-01-27 [SC]
          9D96363D64B579F077AD9446D57583E19B793A64
    uid           [ultimate] Signer <signer@enterprise.com>
    sub   rsa2048 2020-01-27 [E]

    ```

    ```
    $ git clone https://github.com/IBM/integrity-enforcer.git
    $ cd integrity-enforcer
    $ pwd /home/repo/integrity-enforcer
    $ export IE_REPO_ROOT=/home/repo/integrity-enforcer

    ```
   
   3. Sign GRC polices
     
     ```
     $ git clone https://github.com/IBM/integrity-enforcer.git
     $ pwd /home/repo/integrity-enforcer
     $ export IV_REPO_ROOT=/home/repo/integrity-enforcer
     ```
     
     Before execute the make command, setup local environment as follows:
     - IV_REPO_ROOT=<set absolute path of the root directory of cloned integrity-verifier source repository>
    
     The following example shows how to set up a local envionement.

     $ export KUBECONFIG=~/kube/config/target_cluster
     $ export IV_REPO_ROOT=/home/repo/integrity-enforcer

     Then, execute the sample script `ocm-sign-policy.sh`in `scripts` dir to apply signature annotations on YAML resources in a directory.
    
     ```
     cd integrity-verifier/scripts
     $./ocm-sign-policy.sh signer@enterprise.com <YAML-RESOURCES=DIRECTORY>
     ```
     
     Usage: ocm-sign-policy.sh <signer> <YAML files directory>
      - <signer>: Use the `signer` setup above e.g. `signer@enterprise.com`
      - <YAML files directory>:  The directory where the YAML to be signed exist. (e.g. `/home/repo/policy-collection/community`  for signing policies under `community directory' in ACM policy collection (GIT] (https://github.com/open-cluster-management/policy-collection.git))
     
    
6. Deploy signed polices

    The following command deploys polices under `community` to an ACM hub cluster.
      
    ```
    $ cd policy-collection/deploy
    $ bash ./deploy.sh https://github.com/open-cluster-management/policy-collection.git community policies
    ```
      
7. Confirm if `integrity-verifier` is running successfully in a managed cluster.
    
    Check if there are two pods running in the namespace `integrity-verifier-operator-system`: 
        
    ```
    $ oc get pod -n integrity-verifier-operator-system
    integrity-verifier-operator-c4699c95c-4p8wp   1/1     Running   0          5m
    integrity-verifier-server-85c787bf8c-h5bnj    2/2     Running   0          82m
    ```      
    
    
