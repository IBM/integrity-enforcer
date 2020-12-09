
# How to enable Integrity Verifier protection in an ACM managed cluster.

The document describe how to enable Integrity Verifier (IV) protection in an ACM managed cluster to protect integrity of Kubernetes resources. In this usecase, you will see how to protect integrity of [ACM policies](https://github.com/open-cluster-management/policy-collection). 

## Prerequisites

The following prerequisites must be satisfied to enable Integrity Verifier protection in an ACM managed cluster. 

- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command.
- IV requires a pair of keys for signing and verifying signatures of resources that need to be protected in a cluster. Refer to [doc](../README_VERIFICATION_KEY_SETUP.md) for setting up signing and verification keys. 
- The script for deploying a verification key to an ACM managed cluster requires [yq](https://github.com/mikefarah/yq) installed on the host where we run the script.
-  Make sure it is possible to create new dedicated namespaces in the ACM hub cluster and managed clusters.
  - Creating namespace for IV in ACM managed cluster is handled automatically when deploying it via an ACM policy.   
- Installation steps requires a host where we run the scripts.  Below steps are tested on Mac OS and Ubuntu hosts. 
- Enabling Integrity Verifier protection and signing ACM polices involve retriving and commiting sources from GitHub repository. Make sure to install [git](https://github.com/git-guides/install-git) on the host. 

## Steps for enabling Integrity Verifier protection

Enabling Integrity Verifier on an ACM managed cluster requires the following steps:
- Step 1: Prepare a namespace in an ACM hub cluster. 
- Step 2: Deploy a verification key to an ACM managed cluster(s).
- Step 3: Create the ACM policy called `policy-integrity` in the ACM hub cluster.

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
   
   Integrity Verifier requires a secret in an ACM managed cluster(s), that includes a pubkey ring for verifying signatures of resources that need to be protected. 
   To see how to deploy a verification key to an ACM managed cluster, refer to [doc](README_SETUP_KEY_RING_ACM_ENV.md)
    


### Step 3: Create the ACM policy called `policy-integrity` in the ACM hub cluster.
   
   You will use the ACM policy called `policy-integrity`, which is specified in [policy-integrity.yaml](https://github.com/open-cluster-management/policy-collection/blob/master/community/CM-Configuration-Management/policy-integrity.yaml), to enable Integrity Verifier protection in an ACM managed cluster(s).

   The following steps shows how to retrive `policy-integrity` and configure it. 
   
 1. Retrive the source from [policy-collection](https://github.com/open-cluster-management/policy-collection) Git repository.
   
      Fork [policy-collection](https://github.com/open-cluster-management/policy-collection) GitHub repository.  
   
      Then, `git clone` the forked repository and move to `policy-collection` directory.
      
      - Change `https://github.com/<YOUR-ORG-NAME>/policy-collection.git` to your forked repository.

      ```
        $ git clone https://github.com/<YOUR-ORG-NAME>/  policy-collection.git
        $ cd policy-collection
      ```
  2. Configure `policy-integrity.yaml`, which is an ACM policy for enabling Integrity Verifier protection in an ACM managed cluster(s)

      You can find `policy-integrity.yaml` in the directory `policy-collection/community/CM-Configuration-Management/` of the cloned GitHub repository.

      a) Configure the namespace to deploy Integrity Verifier in an ACM managed cluster(s)


      By default, `policy-integrity.yaml` specifies a namespace called `integrity-verifier-operator-system` to be created in an ACM managed cluster(s).

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
       $ git add community/CM-Configuration-Management/policy-integrity.yaml
       $ git commit -m "policy integrity is configured"
       $ git push origin master
       ```
      
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

      Confirm the status (i.e. Compliance) of `policy-integrity` in the ACM hub cluster. You can find `policy-integrity` in the ACM Multicloud webconsole (Governace and Risk). Compliance status of `policy-integrity` means that `policy-integrity` is also created in an ACM managed cluster(s). This will trigger the deployment of Integrity Verifier operator to an ACM managed cluster(s), in the target namespace specified in the `policy-integrity`.

      c) Enable Integrity Verifiier protection in an ACM managed cluster (GitOps).

      After confirming compliance status of `policy-integrity` in the ACM hub cluster, you can enable Integrity Verifier protection in an ACM managed cluster(s) as follows.

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
              include: ["integrity-verifier-operator-system"]
            object-templates:
            - complianceType: musthave <<CHANGED FROM mustnothave>>
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
      Commit the above configuration change in `policy-integrity.yaml` to `policy-collection` GitHub repository.

      The following example shows how to commit your custom `policy-integrity.yaml` to `policy-collection` GitHub repository.

      ```
       $ cd policy-collection
       $ git add community/CM-Configuration-Management/policy-integrity.yaml
       $ git commit -m "Configuration changed in policy integrity"
       $ git push origin master
      ```

      Once the updated `policy-integrity` in the GitHub repository is synced by ACM hub cluster, Integrity Verifier protection in an ACM managed cluster(s) will be enabled. You can confirm this by the compliance status of `policy-integrity` in the ACM hub cluster.
      
      After enabling Integrity Verifier protection, if you need to make changes to any ACM policy deployed in an ACM managed cluster(s), you will need to follow the steps describe below.


## Steps for signing an ACM Policy

  1. Go to the source of your cloned `policy-collection` GitHub repository in the host.  
   Find `policy-ocp4-certs.yaml` in the directory `policy-collection/community/SC-System-and-Communications-Protection/` of the cloned GitHub repository.

  2. Change a configuration in `policy-ocp4-certs.yaml`

      The following example shows `minimumDuration` is changed from `400h` to `100h`
     ```
      - objectDefinition:
          apiVersion: policy.open-cluster-management.io/v1
          kind: CertificatePolicy
          metadata:
            name: openshift-cert-policy
          spec:
            remediationAction: inform
            minimumDuration: 100h << CHANGED from 400h to 100h>>
     ```

  3. Create signature annotation in `policy-ocp4-certs.yaml` as below.

      Use the utility script [gpg-annotation-sign.sh](https://github.com/open-cluster-management/integrity-verifier/blob/master/scripts/gpg-annotation-sign.sh) for signing updated `policy-integrity` to be deployed to an ACM managed cluster.

      The following example shows how to use the utility script [gpg-annotation-sign.sh] to append signature annotations to `policy-ocp4-certs.yaml`, with the following parameters:
      - `signer@enterprise.com` - The default `signer` email, or change it to your own `signer` email.
      - `SC-System-and-Communications-Protection/policy-ocp4-certs.yaml` - the relative path of the updated policy file `policy-ocp4-certs.yaml`

      ```
      $ cd policy-collection
      $ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/gpg-annotation-sign.sh | bash -s \
                    signer@enterprise.com \
                    community/SC-System-and-Communications-Protection/policy-ocp4-certs.yaml
      ```

 4.  Commit the signed `policy-ocp4-certs.yaml` file to the forked `policy-collection` GitHub repository.

      The following example shows how to commit the signed polices files to the forked`policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git status
       $ git add -u
       $ git commit -m "Config changed and signature added to updated policy-egress-firewall-sample.yaml"
       $ git push origin master
       ```  

      Confirm the status (i.e. Compliance) of `policy-cert-ocp4` policy in the ACM hub cluster. You can find `policy-cert-ocp4` policy in the ACM Multicloud webconsole (Governace and Risk). Compliance status of `policy-cert-ocp4` policy means that `policy-cert-ocp4` is updated in an ACM managed cluster(s) after the succesfull signature verification by Integrity Verifier.
