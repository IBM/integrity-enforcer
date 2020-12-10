
# How to enable Integrity Shield protection in an ACM managed cluster.

The document describe how to enable Integrity Shield (IShield) protection in an ACM managed cluster to protect integrity of Kubernetes resources. In this usecase, you will see how to protect integrity of [ACM policies](https://github.com/open-cluster-management/policy-collection). 

## Prerequisites

The following prerequisites must be satisfied to enable Integrity Shield protection in an ACM managed cluster. 

- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command.
- IShield requires a pair of keys for signing and verifying signatures of resources that need to be protected in a cluster. Refer to [doc](../README_VERIFICATION_KEY_SETUP.md) for setting up signing and verification keys. 
- The script for deploying a verification key to an ACM managed cluster requires [yq](https://github.com/mikefarah/yq) installed on the host where we run the script.
-  Make sure it is possible to create new dedicated namespaces in the ACM hub cluster and managed clusters.
  - Creating namespace for IShield in ACM managed cluster is handled automatically when deploying it via an ACM policy.   
- Installation steps requires a host where we run the scripts.  Below steps are tested on Mac OS and Ubuntu hosts. 
- Enabling Integrity Shield protection and signing ACM polices involve retriving and commiting sources from GitHub repository. Make sure to install [git](https://github.com/git-guides/install-git) on the host. 

## Steps for enabling Integrity Shield protection

Enabling Integrity Shield on an ACM managed cluster requires the following steps:
- Step 1: Prepare a namespace in an ACM hub cluster. 
- Step 2: Deploy a verification key to an ACM managed cluster(s).
- Step 3: Create the ACM policy called `policy-integrity` in the ACM hub cluster.

### Step 1: Prepare a namespace in an ACM hub cluster. 
Connect to the ACM Hub cluster and execute the following command:

```
oc create ns integrity-shield-operator-system
```
The above command will create a namespace `integrity-shield-operator-system` in the ACM hub cluster.

By default, we use `integrity-shield-operator-system` in this document.
If you prefer to call the namespace something else, you can run the following instead: 
 
```
oc create ns <custom namespace> 
```

### Step 2:  Deploy a verification key to an ACM managed cluster. 
   
   Integrity Shield requires a secret in an ACM managed cluster(s), that includes a pubkey ring for verifying signatures of resources that need to be protected. 
   To see how to deploy a verification key to an ACM managed cluster, refer to [doc](README_SETUP_KEY_RING_ACM_ENV.md)
    


### Step 3: Create the ACM policy called `policy-integrity` in the ACM hub cluster.
   
   You will use the ACM policy called `policy-integrity`, which is specified in [policy-integrity.yaml](https://github.com/open-cluster-management/policy-collection/blob/master/community/CM-Configuration-Management/policy-integrity.yaml), to enable Integrity Shield protection in an ACM managed cluster(s).

   The following steps shows how to retrive `policy-integrity` and configure it. 
   
 1. Retrive the source from [policy-collection](https://github.com/open-cluster-management/policy-collection) Git repository.
   
      Fork [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository.  
   
      Then, `git clone` the forked repository and move to `policy-collection` directory.
      
      - Change `https://github.com/<YOUR-ORG-NAME>/policy-collection.git` to your forked repository.

      ```
        $ git clone https://github.com/<YOUR-ORG-NAME>/  policy-collection.git
        $ cd policy-collection
      ```
  2. Configure `policy-integrity.yaml`, which is an ACM policy for enabling Integrity Shield protection in an ACM managed cluster(s)

      You can find `policy-integrity.yaml` in the directory `policy-collection/community/CM-Configuration-Management/` of the cloned GitHub repository.

      a) Configure the namespace to deploy Integrity Shield in an ACM managed cluster(s)


      By default, `policy-integrity.yaml` specifies a namespace called `integrity-shield-operator-system` to be created in an ACM managed cluster(s).

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
                  kind: Namespace # must have namespace 'integrity-shield-operator-system'
                  apiVersion: v1
                  metadata:
                    name: integrity-shield-operator-system
        ```

        If you use your custom namespace in Step 1, change all instances of  `integrity-shield-operator-system` to your custom namespace in `policy-integrity.yaml`.

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

      The [placement rule](https://github.com/open-cluster-management/policy-collection) in `policy-integrity.yaml` determines which ACM managed clusters Integrity Shield should be deployed.  

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
      The above `placement rule` configures that Integrity Shield to be deployed to an ACM managed cluster(s) with tags: 
        - key: `environment` 
        - values: `dev`

      If you would like to use your own tags for selecting ACM managed clusters as target for deploying IShield, change the above tags to your own.

  3. Enable `policy-integrity` on an ACM managed cluster (GitOps).
  
      a)  Commit your changed configuration in `policy-integrity.yaml` to the `policy-collection` GitHub repository that you cloned earlier, if you have customized as described above.

      If you have not customized `policy-integrity.yaml`, skip this step.
      
      b)  Create a new namespace (e.g. `policy-community`) in the ACM hub cluster to deploy `policy-integrity`. 
      ```
      oc create ns policy-community
      ```
      c)  Create `policy-integrity` in the ACM hub cluster in newly created namespace.

      Connect to the ACM Hub cluster and execute the following script with the following parameters:
        - https://github.com/YOUR-ORG-NAME/policy-collection.git -  The URL for the forked `policy-collection` GitHub reposiory. 
        - `community` - The directory where `policy-integrity.yaml` is located.
        -  `policy-community` - The namespace for creating policy   

      ```
        $ cd policy-collection/deploy
        $ bash ./deploy.sh  https://github.com/<YOUR-ORG-NAME>/policy-collection.git community policy-community
      ``` 
    
      Refer to general instructions to deploy ACM policies to an ACM hub cluster as well as ACM managed cluster(s) using GitOps in [doc](https://github.com/open-cluster-management/policy-collection).

      After ACM hub cluster syncs the polices in the GitHub repository, an ACM policy called `policy-integrity`  will be created in the ACM hub cluster and in an ACM managed cluster(s) which are selected based on the placement rule in the policy. 
      
      Wait for few mintutes for policies to be setup in the ACM hub cluster and managed cluster(s)

      Confirm the status (i.e. Compliance) of `policy-integrity` in the ACM hub cluster. You can find `policy-integrity` in the ACM Multicloud webconsole (Governace and Risk). Compliance status of `policy-integrity` means that `policy-integrity` is also created in an ACM managed cluster(s). This will trigger the deployment of Integrity Shield operator to an ACM managed cluster(s), in the target namespace specified in the `policy-integrity`.

      c) Enable Integrity Verifiier protection in an ACM managed cluster (GitOps).

      After confirming compliance status of `policy-integrity` in the ACM hub cluster, you can enable Integrity Shield protection in an ACM managed cluster(s) as follows.

      Change the `complianceType` configuration for `integrity-cr-policy` from `mustnothave` to `musthave` in `policy-integrity.yaml` in the directory `policy-collection/community/CM-Configuration-Management/` of the cloned GitHub repository.

      The following example shows the `complianceType` configuration for `integrity-cr-policy` changed from `mustnothave` to `musthave`.

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
              include: ["integrity-shield-operator-system"]
            object-templates:
            - complianceType: musthave <<CHANGED FROM mustnothave>>
              objectDefinition:
                apiVersion: apis.integrityshield.io/v1alpha1
                kind: IntegrityShield
                metadata:
                  name: integrity-shield-server
                spec:
                  logger:
                    image: quay.io/open-cluster-management/integrity-shield-logging:0.1.0
                  server:
                    image: quay.io/open-cluster-management/integrity-shield-server:0.1.0
      ```
      Commit the above configuration change in `policy-integrity.yaml` to `policy-collection` GitHub repository.

      Once the updated `policy-integrity` in the GitHub repository is synced by ACM hub cluster, Integrity Shield protection in an ACM managed cluster(s) will be enabled. You can confirm this by the compliance status of `policy-integrity` in the ACM hub cluster.
      
      After enabling Integrity Shield protection, if you need to make changes to any ACM policy deployed in an ACM managed cluster(s), you will need to follow the steps describe below.


## Steps for signing an ACM Policy

You can just sign any policy in your GitOps source of policies in `policy-collection`.

Here is the example when you sign the policy policy-ocp4-certs.yaml with the key of signer signer@enterprise.com:


```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-annotation-sign.sh | bash -s \
              signer@enterprise.com \
              policy-ocp4-certs.yaml
```

- This script will modify the original file. If you would like to keep the original file, keep a backup of the file before signing.
- You need to create new signature whenever you change policy and apply it to clusters. Otherwise, the change will be blocked and not applied.
- If you want to sign all policies under some directory, you can use this script iteratively. Here is the example of the script for signing policies in dir:

```
#!/bin/bash

signer = $1
dir = $2

find $dir -type f -name "*.yaml" | while read file;
do
  echo Signing  $file
  curl -s https://raw.githubusercontent.com/open-cluster-management/integrity-shield/master/scripts/gpg-annotation-sign.sh | bash -s $signer "$file"
done
```
