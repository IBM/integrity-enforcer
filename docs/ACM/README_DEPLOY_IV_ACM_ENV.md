
# How to install Integrity Verifier to an ACM managed cluster.

The document describe how to install Integrity Verifier (IV) to an ACM managed cluster to protect [ACM policies](https://github.com/open-cluster-management/policy-collection). 

## Prerequisites

The following prerequisites must be satisfied to deploy IV on an ACM managed cluster. 

- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command.
- IV requires a pair of keys for signing and verifying signatures of ACM polices that need to be protected in a managed cluster. Refer to [doc](../README_VERIFICATION_KEY_SETUP.md) for setting up signing and verification keys. 
- The script for deploying a verification key to an ACM managed cluster requires [yq](https://github.com/mikefarah/yq) installed on the host where we run the script.
- Installing IV requires a namespace (with same name) in an ACM hub cluster and managed clusters. Make sure it is possible to create namespaces in the ACM hub cluster and managed clusters.
  - Creating namespace for IV in managed cluster is handled automatically when deploying it via an ACM policy.   
- Installation steps requires a host where we run the scripts.  Below steps are tested on Mac OS and Ubuntu hosts. 
- Installing IV and signing ACM polices involve retriving and commiting sources from GitHub repository. Make sure to install [git](https://github.com/git-guides/install-git) on the host. 

## Installation Steps

Installing IV on an ACM managed cluster requires the following steps:
- Step 1: Prepare a namespace in an ACM hub cluster. 
- Step 2: Deploy a verification key to an ACM managed cluster
- Step 3: Deploying Integrity Verifier to an ACM managed cluster using an ACM policy.

### Step 1: Prepare a namespace in an ACM hub cluster. 
Connect to the ACM Hub cluster and execute the following command:

```
oc create ns integrity-verifier-operator-system
```
The above command will create a namespace `integrity-verifier-operator-system` in the ACM hub cluster.

By default, we use `integrity-verifier-operator-system` in this document.
If you prefer to call the namespace something else, you can run the following instead: 
 
```
oc create ns <custom namespace> 
```

### Step 2:  Deploy a verification key to an ACM managed cluster. 
   
   Integrity Verifier requires a secret in an ACM managed cluster(s), that includes a pubkey ring for verifying signatures of ACM polices that need to be protected. 
   To see how to deploy a verification key to an ACM managed cluster, refer to [doc](README_SETUP_KEY_RING_ACM_ENV.md)
    


### Step 3: Deploying Integrity Verifier to an ACM managed cluster using an ACM policy.
   
   We will use an ACM policy called `policy-integrity`, which is specified in [policy-integrity.yaml](https://github.com/open-cluster-management/policy-collection/blob/master/community/integrity/policy-integrity.yaml), to deploy Integrity Verifier to an ACM managed cluster(s).

   The following steps shows how to retrive ACM policies and customize them. 
   
 1. Retrive the source from [policy-collection](https://github.com/open-cluster-management/policy-collection) Git repository.
   
      Fork [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository. We will use the forked version of this repo as the target to run the sync against when deploying ACM policies to an ACM cluster. 
   
      Then, `git clone` the forked repository.

      The following example shows how to clone `policy-collection` and move to `policy-collection` directory
       ```
       $ git clone https://github.com/<YOUR-ORG-NAME>/policy-collection.git
       $ cd policy-collection
       ```
  2. Configure `policy-integrity.yaml`, which is an ACM policy for deploying IV to an ACM managed cluster(s)

      You can find `policy-integrity.yaml` in the directory `policy-collection/community/integrity/` of the cloned GitHub repository.

      a)  Configure the Namespace to deploy IV to an ACM managed cluster(s)


      By default, `policy-integrity.yaml` specifies a namespace as `integrity-verifier-operator-system` to be created in an ACM managed cluster(s) for deploying IV.

        ```
          - objectDefinition:
            apiVersion: policy.open-cluster-management.io/v1
            kind: ConfigurationPolicy
            metadata:
              name: integrity-namespace-policy
            spec:
              remediationAction: enforce
              severity: High
              namespaceSelector:
                exclude: ["kube-*"]
                include: ["default"]
              object-templates:
              - complianceType: musthave
                objectDefinition:
                  kind: Namespace # must have namespace 'integrity-verifier-operator-system'
                  apiVersion: v1
                  metadata:
                    name: integrity-verifier-operator-system
        ```

        If you use your custom namespace in Step 1, change all instances of  `integrity-verifier-operator-system` to your custom namespace in `policy-integrity.yaml`.

      b)  Configure a signer's email

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
        If you use your own `signer` for setting up signing and verification keys as described in [doc](../README_VERIFICATION_KEY_SETUP.md), change `signer@enterprise.com` to your own signer's email.

     c)  Configure the placement rule 

      The [placement rule](https://github.com/open-cluster-management/policy-collection) in `policy-integrity.yaml` determines which ACM managed clusters Integrity Verifier should be deployed.  

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

      If you would like to use your own tags for selecting ACM managed clusters as target for deploying IV, change the above tags to your own.

  3. Enable `policy-integrity` on an ACM managed cluster (GitOps).
  
      a)  Commit your changed configuration in `policy-integrity.yaml` to the `policy-collection` GitHub repository that you cloned earlier, if you have customized as described above.

      If you have not customized `policy-integrity.yaml`, skip this step.

      The following example shows how to commit your custom `policy-integrity.yaml` to `policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git add community/integrity/policy-integrity.yaml
       $ git commit -m "policy integrity is configured"
       $ git push origin master
       ```
      
        
      b)  Create `policy-integrity` in the ACM hub cluster.

      Connect to the ACM Hub cluster and execute the following commands to create `policy-integrity` in it. 
        
      Note: Change      

      ```
        $ curl -s https://raw.githubusercontent.com/open-cluster-management/policy-collection/master/deploy/deploy.sh | bash -s  https://github.com/<YOUR-ORG-NAME>/policy-collection.git community policy-community
      ``` 
       
      We pass the following parameters:
        - https://github.com/YOUR-ORG-NAME/policy-collection.git -  The URL for the forked `policy-collection` GitHub reposiory. 
        - `community` - The directory where `policy-integrity.yaml` is located.
    
      The above command will configure your forked `policy-collection` GitHub repository as the target to run the sync against to create `policy-integrity` in the ACM hub cluster.

      General instructions to deploy ACM policies to an ACM hub cluster as well as ACM managed cluster(s) using GitOps can be found in [doc](https://github.com/open-cluster-management/policy-collection).

      After ACM hub cluster syncs the polices in the GitHub repository, an ACM policy called `policy-integrity`  will be created in an ACM managed cluster(s) which are selected based on the placement rule in the policy.

      Successfull creation of `policy-integrity` in an ACM managed cluster(s) will trigger the deployment of IV operator in the target namespace specified in the `policy-integry` in the clusters.

      c) Enable IV server on an ACM managed cluster (GitOps).

      After deploying IV operator using `policy-integrity` in an ACM managed cluster(s),  we will enable IV server.

      For this, change the `complianceType` configuration for `integrity-cr-policy` from `mustnothave` to `musthave`

      After applying the above change, the following example shows the `complianceType` configuration for `integrity-cr-policy`.

      ```
        - objectDefinition:
          apiVersion: policy.open-cluster-management.io/v1
          kind: ConfigurationPolicy
          metadata:
            name: integrity-cr-policy
          spec:
            remediationAction: enforce 
            severity: high
            namespaceSelector:
              exclude: ["kube-*"]
              include: ["integrity-verifier-operator-system"]
            object-templates:
            - complianceType: musthave
              objectDefinition:
                apiVersion: apis.integrityverifier.io/v1alpha1
                kind: IntegrityVerifier
                metadata:
                  name: integrity-verifier-server
                spec:
                  logger:
                    image: quay.io/open-cluster-management/integrity-verifier-logging:0.0.4
                  server:
                    image: quay.io/open-cluster-management/integrity-verifier-server:0.0.4
      ```
      We will commit the above configuration change in `policy-integrity.yaml` to GitHub repository.

      The following example shows how to commit your custom `policy-integrity.yaml` to `policy-collection` GitHub repository.

      ```
       $ cd policy-collection
       $ git add community/integrity/policy-integrity.yaml
       $ git commit -m "Configuration changed in policy integrity"
       $ git push origin master
      ```

      After ACM hub cluster syncs the polices in the GitHub repository, the updated configuration changes in `policy-integrity` will be applied to an ACM managed cluster(s), This will trigger the deployment of IV server in the target namespace specified in the `policy-integry` in the clusters.

## Signing Multiple ACM policies at once.

We will use Integrity Verifier to protect integrity of all `ACM policies` created in an ACM managed cluster(s). For this, IV requires `ACM policies` to be signed.

We describe how to sign ACM polices as below.

 1. Retrive the source from [policy-collection](https://github.com/open-cluster-management/policy-collection) Git repository.
   
      Fork [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository. We will use the forked version of this repo as the target to run the sync against. 
   
      Then `git clone` the forked repository.

      The following example shows how to clone `policy-collection` and move to `policy-collection` directory
       ```
       $ git clone https://github.com/<YOUR-ORG-NAME>/policy-collection.git
       $ cd policy-collection
       ```
  2.  Create signature annotations to ACM policies files in the cloned `policy-collection` GitHub repository.

      We will use the utility script [acm-sign-policy.sh](https://github.com/IBM/integrity-enforcer/blob/master/scripts/acm-sign-policy.sh) for signing ACM polices to be deployed to an ACM managed cluster.

      The following example shows we use the utility script [acm-sign-policy.sh] to append signature annotations to 
      ACM policies files.

      ```
      $ cd policy-collection
      $ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-sign-policy.sh | bash -s \
                    signer@enterprise.com \
                    community
      ```

      We pass the following parameters:
        - `signer@enterprise.com` -   The default signer email used for setting up signing and verification in deploying IV to an ACM managed cluster.  
          - If you use your own `signer` for setting up signing and verification keys as described in [doc](../README_VERIFICATION_KEY_SETUP.md), change `signer@enterprise.com` to your own.

        - `community` - The directory of policy files to be signed.

      The utility script [acm-sign-policy.sh] would append signature annotation to each original file, which is backed up before annotating (e.g. `policy-integrity.yaml`  will be backedup as policy-integrity.yaml.backup).

    
  3.  Commit the signed ACM policies files to the forked`policy-collection` GitHub repository which will be synced with the ACM hub cluster.

      The following example shows how to commit the signed polices files to the forked`policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git status
       $ git add -u
       $ git commit -m "Signature annotation added to ACM policies"
       $ git push origin master
       ```

       Once we commit the signed policy files to the forked `policy-collection` GitHub repository, the signed ACM polices will be synched by the ACM hub cluster to update the deployed ACM policies with signature annotations in the ACM managed cluster(s). Once the signature annotations are updated to the deployed ACM policies, IV will protect thier integrity.  Any further changes requires the policy signing process described above.

## Uninstall the installed IV from an ACM managed cluster(s)

We will use `policy-integrity` to uninstall Integrity Verifier from an ACM managed cluster(s) as described below.


 1. Retrive the source from [policy-collection](https://github.com/open-cluster-management/policy-collection) Git repository.
   
      Fork [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository. We will use the forked version of this repo as the target to run the sync against. 
   
      Then `git clone` the forked repository.

      The following example shows how to clone `policy-collection` and move to `policy-collection` directory
       ```
       $ git clone https://github.com/<YOUR-ORG-NAME>/policy-collection.git
       $ cd policy-collection
       ```

 2. Change `policy-integrity` content as below.     
    
    In ``policy-integrity.yaml` file, we wil change the `complianceType` configuration from `musthave` to `mustnothave` for the following ConfigurationPolicies:
    - `integrity-namespace-policy`
    - `integrity-og-policy`
    - `integrity-catrsc-policy`
    - `integrity-sub-policy`
    - `integrity-cr-policy` 


    After applying the above change, the following example shows the `complianceType` configuration for `integrity-namespace-policy`

    ```
    - objectDefinition:
      apiVersion: policy.open-cluster-management.io/v1
      kind: ConfigurationPolicy
      metadata:
        name: integrity-namespace-policy
      spec:
        remediationAction: enforce
        severity: High
        namespaceSelector:
          exclude: ["kube-*"]
          include: ["default"]
        object-templates:
        - complianceType: mustnothave
          objectDefinition:
            kind: Namespace 
            apiVersion: v1
            metadata:
              name: integrity-verifier-operator-system
    ```
 3. Afte applying above change in `policy-integrity.yaml`, create signature annotations as below.

    We will use the utility script [acm-sign-policy.sh](https://github.com/IBM/integrity-enforcer/blob/master/scripts/acm-sign-policy.sh) for signing ACM polices to be deployed to an ACM managed cluster.

      The following example shows we use the utility script [acm-sign-policy.sh] to append signature annotations to 
      ACM policies files.

      ```
      $ cd policy-collection
      $ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-sign-policy.sh | bash -s \
                    signer@enterprise.com \
                    community/integrity
      ```

 4.  Commit the signed `policy-integrity.yaml` file to the forked `policy-collection` GitHub repository which will be synced with the ACM hub cluster.

      The following example shows how to commit the signed polices files to the forked`policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git status
       $ git add -u
       $ git commit -m "Signature annotation added to ACM policies"
       $ git push origin master
       ```   

       ACM hub cluster will sync the latest `policy-integrity` from GitHub repository to the ACM managed cluster(s). This will trigger unstalling IV server, IV operator, IV namespace.

  5.  Remove `policy-integrity` from ACM managed cluster(s)

      By default, `policy-integrity.yaml` includes a `placement rule` as shown in the following example. In such case, change the values as below.

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
             - {key: environment, operator: In, values:   ["-"]}
      ```   
    6.  Commit the changes in `policy-integrity.yaml` file to the forked `policy-collection` GitHub repository which will be synced with the ACM hub cluster.

      The following example shows how to commit the signed polices files to the forked`policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git status
       $ git add -u
       $ git commit -m "Placement rule changed."
       $ git push origin master
       ```   

       ACM hub cluster will sync the latest `policy-integrity` from GitHub repository to the ACM managed cluster(s). This will trigger unstalling `policy-integrity` from the ACM managed cluster(s).  

     


   