# Integrity Enforcer (IE)

## Supported Platforms

Integrity Enforcer aims to provide a built-in mechanism for preventing integrity violation to resources on a cluster. IE currently supports the following platforms:

- [ROKS](https://cloud.ibm.com/docs/openshift)
- RedHat OpenShift 4.3 (e.g. OCP on AWS)
- Minikube

## Prerequisites
see documentation [here](README_PREREQUISITES.md)
 
## Tips
- see installation tips for minikube [here](README_FOR_MINIKUBE_ENV.md)
- see installation tips for OCP [here](README_FOR_OCP_ENV.md)

## Installation via CLI

This document describe steps for deploying Integrity Enforcer (IE) on your RedHat OpenShift cluster including ROKS via `oc` or `kubectl` CLI commands. 

- Deploy admission webhook via Integrity Enforcer operator

---
## Deploy admission webhook via Integrity Enforcer operator
  
  Install `integrity-enforcer-operator` on ROKS as follows.

First, clone this repository and moved to `integrity-enforcer` directory
```
git clone git@github.com:IBM/integrity-enforcer.git
cd integrity-enforcer
```

Create a namespace (if not exist).

```
oc create ns integrity-enforcer-ns
```

Change label

```
oc label namespace integrity-enforcer-ns integrity-enforced=true
```

1. Switch to enforcer namespace

    ```
    oc project integrity-enforcer-ns
    ```

2. Do the following commands to deploy `integrity-enforcer` operator
    
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

4. After successfully installing the operator, create a `integrity-enforcer` server.
    
    Note: check [configuration](README_CONFIGURATION.md)
    
    deploy webhook server `integrity-enforcer-server` by creating custom resource for IE by
    ```     
    $ oc create -f deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml
    ```
    
    Check if the pods are running properly. It takes about a minute to get runnning state.
    ```
    $ oc get pod | grep 'integrity-enforcer-server'
    integrity-enforcer-server-85c787bf8c-h5bnj    2/2     Running   0          82m
    ```

4. Create a namespace `ie-sign` for creating signatures and set it as a protected namespace

    ```
    oc create ns ie-sign
    oc label ns ie-sign integrity-enforced=true    
    ```
5.  Create a namespace `ie-policy` for creating custom policies and set it as a protected namespace

    ```
    oc create ns ie-policy
    oc label ns ie-policy integrity-enforced=true    
    ```   
---

## Upgrade
