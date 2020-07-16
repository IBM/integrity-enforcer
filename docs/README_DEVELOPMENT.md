# Integrity Enforcer (IE)

## Development
This document describe tasks involved in developing new features or changing any existing for Integrity Enforcer (IE) and deploying them on a cluster. There are two key steps: 
- Build: The steps involved in building the source code and building container images and pushing them to container registry etc.
- Deployment: The steps involved in deploying after upgradeing `Integrity-Enforcer`
- Signing Service Tool: This could be used for signing resources to be deployed on a cluster where integrity enforcement is enabled via IE.  Signing Service tool returns a resource signature for a given resource input as yaml.

## Build

First, clone this repository and moved to integrity-enforcer directory

```
git clone git@github.ibm.com:mutation-advisor/integrity-enforcer.git
cd integrity-enforcer
```

Make changes to source code as needed.

Start building source code as well container images

```
$./develop/scripts/build_images.sh
```

Push container images to registry

Note:  Setup container image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed 

```
$./develop/scripts/push_images.sh
```

## Deployment

Depending on the changes made, it may be required to re-deploy `Integrity-Enforcer` all over again.

1. Delete `Integrity-Enforcer` from cluster

   run the following commands.
   ```
    cd operator
    
    # Delete CR `integrity-enforcer`  
    oc delete -f deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml 

    # Delete Operator    
    oc delete -f deploy/service_account.yaml
    oc delete -f deploy/role.yaml
    oc delete -f deploy/role_binding.yaml
    oc delete -f deploy/operator.yaml

    # Delete CRD
    oc delete -f deploy/crds/research.ibm.com_integrityenforcers_crd.yaml
   ```
   
2. Deploy `Integrity-Enforcer` again.

   run the following commands to deploy `integrity-enforcer` operator
   ```
    cd operator

    # Create CRDs

    oc create -f deploy/crds/research.ibm.com_integrityenforcers_crd.yaml

    # Deploy `integrity-enforcer operator`    

    oc create -f deploy/service_account.yaml 
    oc create -f deploy/role.yaml 
    oc create -f deploy/role_binding.yaml 
    oc create -f deploy/operator.yaml
    ```

3. Confirm if IE operator is running properly.

    ```
    $ oc get pod | grep integrity-enforcer-operator
    integrity-enforcer-operator-c4699c95c-4p8wp   1/1     Running   0          5m
    ```
    
4. After successfully installing the operator, create a integrity-enforcer server.
    
    deploy webhook server integrity-enforcer-server by creating custom resource for IE by
    
    ```
    $ oc create -f deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml
    ```
    
    Check if the pods are running properly. It takes about a minute to get runnning state.

    ```
    $ oc get pod | grep 'integrity-enforcer-server'
    integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
    ```
    
## Signing Service Tool

   The followins are the steps building source code and container images for signing service.
   
   Start building source code as well container images

   ```
   $./develop/signservice/develop/scripts/build_images.sh
   ```

   Push container images to registry

   Note:  Setup container image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed 

   ```
   $./develop/signservice/develop/scripts/push_images.sh
   ```

   see documention [here](README_INSTALL_SIGNING_SERVICE.md) for deploying signing service.

