
# How to install Integrity Verifier to an ACM managed cluster.

The document describe how to deploy Integrity Verifier to an ACM managed cluster.

## Prerequisites

The following prerequisites must be satisfied to deploy Integrity Verifier on an ACM managed cluster via [ACM policies](https://github.com/open-cluster-management/policy-collection).
- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command
- PGP key setup. To see how to setup PGP key,  refer to [doc](../README_VERIFICATION_KEY_SETUP.md)
- A secret resource (keyring-secret) which contains a public key should be setup on an ACM managed cluster for enabling signature verification by Integrity Verifier.

## Deploy a verification key to an ACM managed cluster. 
   
   Integrity Verifier requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected. In this, we need to setup a verification key on an ACM managed cluster(s). To see how to deploy a verification key to an ACM managed cluster, refer to [doc](README_SETUP_KEY_RING_ACM_ENV.md)
    
## Deploying ACM polices to an ACM managed cluster.
  An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) syncs [ACM policies](https://github.com/open-cluster-management/policy-collection) hosted in a git hub repository to an ACM hub cluster as well as to an ACM managed cluster(s) using GitOps.
  
   
## Deploying Integrity Verifier to an ACM managed cluster using ACM polices.

   We will use [policy-integrity.yaml](https://github.com/gajananan/policy-collection/blob/master/community/integrity/policy-integrity.yaml) to deploy Integrity Verifier on an ACM managed cluster.
  
   1. Retrive the source from `policy-collection` Git repository.
   
      Fork [this repository]https://github.com/gajananan/policy-collection; you will use the forked version of this repo as the target to run the sync against. 
   
      Them `git clone` the forked repository.

      The following example shows how to clone `policy-collection` and move to `policy-collection` directory
       ```
       $ git clone https://github.com/gajananan/policy-collection.git
       $ cd policy-collection
       $ pwd /home/repo/policy-collection
       ```
       In this document, we clone the code in `/home/repo/policy-collection`.
    
   2. Setup `policy-integrity.yaml`
       
      First include signer email used for setting up signer and verification keys.  refer to [doc](../README_VERIFICATION_KEY_SETUP.md).
      The following example shows `signer@enterprise.com` is added.
      
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
        
        Next, specift the [placement rule](https://github.com/open-cluster-management/policy-collection) to select which clusters Integrity Verifier should be deployed.  The following example shows Integrity Verifier should be deployed to an ACM managed cluster(s) with key `environment` and values `dev`
        
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
             - {key: environment, operator: In, values: ["dev"]}
         ```
   
   2. Using GitOps to deploy policies to a cluster     

      Follow the [doc](https://github.com/open-cluster-management/policy-collection) to deploy ACM policies to an ACM hub cluster as well as managed cluster(s) using GitOps.
   
      The following example shows we use `policy-community` as default namespace for deploying policy: `policy-integrity.yaml` which is in `community/integrity` directory, to an ACM hub cluster. 
        
       ```
       $ cd policy-collection/deploy
       $ bash ./deploy.sh https://github.com/open-cluster-management/policy-collection.git community/integrity policy-community
       
       ```
 
## Signing ACM policies.
 
  We will use the script: [acm-sign-policy.sh](https://github.com/IBM/integrity-enforcer/blob/master/scripts/acm-sign-policy.sh) for signing ACM polices cloned from git [https://github.com/gajananan/policy-collection.git].
  
  Pass the following parameters. 
 
   - SIGNER-EMAIL-USED-IN-PGP-KEYSETUP: Use the email used in setting a PGP key (e.g. `signer@enterprise.com`).  
   - POLICY-FILES-DIRECTORY:  The directory where the [ACM policy](https://github.com/open-cluster-management/policy-collection.git) files (YAML) to be signed exist. (e.g.  Pass `/home/repo/policy-collection/community` as dir to sign polices under `community` directory).
   
 Execute the sample script `acm-sign-policy.sh` to apply signature annotations on YAML resources in a directory.
    
 ```
  $ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-sign-policy.sh | bash -s \
                 <SIGNER-EMAIL-USED-IN-PGP-KEYSETUP> \
                 <POLICY-FILES-DIRECTORY>
 ```
 Note:  `acm-sign-policy.sh` script would annotate the YAML files in the directory <YAML-RESOURCES=DIRECTORY>. Make a backup of YAML files if you need.
     
   
## Persit signed ACM policies to the git hub repository   
 
 We will commit the signed policy files to git hub repostitory which will be used by ACM as the target to run the sync against so that signed ACM polices will be deployed to ACM hub and managed cluster(s).
 
 ```
 $ cd policy-collection
 $ git add community
 $ git commit -m "Signature annotation added to policies"
 $ git push origin master
 ```
 
 

   
   
   
   
