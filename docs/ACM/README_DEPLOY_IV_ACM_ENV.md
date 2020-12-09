
# How to install Integrity Verifier to an ACM managed cluster.

The document describe how to install Integrity Verifier (IV) to an ACM managed cluster to protect [ACM policies](https://github.com/open-cluster-management/policy-collection). 

## Prerequisites

The following prerequisites must be satisfied to deploy IV on an ACM managed cluster. 

- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command.
- IV requires a pair of keys for signing and verifying signatures of ACM polices that need to be protected in a managed cluster. IV supports X509 or PGP key for signing/verifying resources. Refer to [doc](../README_VERIFICATION_KEY_SETUP.md) for setting up signing and verification keys. 
- The script for deploying a verification key to an ACM managed cluster requires [yq](https://github.com/mikefarah/yq) installed on the host where we run the script.
- Installing IV requires a namespace (with same name) in an ACM hub cluster and managed clusters. Make sure it is possible to create namespaces in the ACM hub cluster and managed clusters.
  - Creating namespace for IV in managed cluster is handled automatically when deploying it via an ACM policy.   
- Installation steps requires a host where we run the scripts.  Below steps are tested on Mac OS and Ubuntu hosts.   

## Installation Steps

Installing IV on an ACM managed cluster requires the following steps:
- Step 1: Prepare a namespace in an ACM hub cluster. 
- Step 2: Deploy a verification key to an ACM managed cluster
- Step 3: Deploying Integrity Verifier to an ACM managed cluster using ACM polices.

### Step 1: Prepare a namespace in an ACM hub cluster. 
Connect to the ACM Hub cluster and execute the following command:

```
oc create ns integrity-verifier-operator-system
```
The above command will create a namespace `integrity-verifier-operator-system` in the ACM hub cluster.

### Step 2:  Deploy a verification key to an ACM managed cluster. 
   
   Integrity Verifier requires a secret in an ACM managed cluster(s), that includes a pubkey ring for verifying signatures of ACM polices that need to be protected. 
   To see how to deploy a verification key to an ACM managed cluster, refer to [doc](README_SETUP_KEY_RING_ACM_ENV.md)
    


### Step 3: Deploying Integrity Verifier to an ACM managed cluster using ACM polices.
   
   We will use [policy-integrity.yaml](https://github.com/open-cluster-management/policy-collection/blob/master/community/integrity/policy-integrity.yaml) to deploy Integrity Verifier on an ACM managed cluster.
   
   
 1. Retrive the source from [policy-collection](https://github.com/open-cluster-management/policy-collection) Git repository.
   
      Fork [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository. We will use the forked version of this repo as the target to run the sync against. 
   
      Then `git clone` the forked repository.

      The following example shows how to clone `policy-collection` and move to `policy-collection` directory
       ```
       $ git clone https://github.com/gajananan/policy-collection.git
       $ cd policy-collection
       ```
  2. Configure `policy-integrity.yaml`, which is an ACM policy for deploying IV to an ACM managed cluster(s)
    
        a)  Configure a signer

        By default, `policy-integrity.yaml` includes a signer (`signer@enterprise.com`) as shown in following example.
      
        ``` 
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
        If you use your own `signer` for setting up signing and verification keys as described in [doc](../README_VERIFICATION_KEY_SETUP.md), change `signer@enterprise.com` to your own.

     b)  Configure the [placement rule](https://github.com/open-cluster-management/policy-collection) to select which ACM managed clusters Integrity Verifier should be deployed.  

      By default, `policy-integrity.yaml` includes a `placement rule` as shown in the following example. 

      ```
         apiVersion: apps.open-cluster-management.io/v1
         kind: PlacementRule
         metadata:
           name: placement-integrity-policy
         spec:
           clusterConditions:
           - status: "True"
             type: ManagedClusterConditionAvailable
           clusterSelector:
             matchExpressions:
             - {key: environment, operator: In, values:   ["dev"]}
      ```   
      The above `placement rule` configures that Integrity Verifier to be deployed to an ACM managed cluster(s) with tags: 
        - key: `environment` 
        - values: `dev`

      If you would like to use your own tags for selecting ACM managed clusters, change the above tags to your own.

  3. Create `policy-integrity.yaml` on an ACM managed cluster.
  
      a)  Commit the `policy-integrity.yaml` to forked `policy-collection` GitHub repository, if you have customized as described above.

      The following example shows how to check in configured `policy-integrity.yaml` to `policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git add community/integrity/policy-integrity.yaml
       $ git commit -m "policy integrity is configured"
       $ git push origin master
       ```

       If you have not customized `policy-integrity.yaml`, skip this step.
        
      a)  Deploy `policy-integrity.yaml` to an ACM hub cluster.

      Connect to the ACM Hub cluster and execute the following commands to deploy `policy-integrity.yaml` to it.

       The following example shows we use `policy-community` as a namespace for deploying `policy-integrity.yaml`, which is in `community/integrity` directory, to an ACM hub cluster.  
        
       ```
        $ curl -s https://raw.githubusercontent.com/open-cluster-management/policy-collection/master/deploy/deploy.sh | bash -s  https://github.com/open-cluster-management/policy-collection.git community/integrity policy-community
       ``` 
      
       The above command will configure [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository as the target to run the sync against to deploy `policy-integrity.yaml` found in `community/integrity` directory to the ACM hub cluster.
    
      General instructions to deploy ACM policies to an ACM hub cluster as well as ACM managed cluster(s) using GitOps can be found in [doc](https://github.com/open-cluster-management/policy-collection) .