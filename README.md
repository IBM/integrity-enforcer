# integrity-enforcer
Integrity Enforcer is a tool for built-in preventive integrity control for regulated cloud workloads. It includes signature based configuration drift prevention based on Admission Webhook on Kubernetes cluster.

Integrity Enforcer's capabilities are 

- Allow to deploy authorized application pakcages only
- Allow to use signed deployment params only
- Zero-drift in resource configuration unless whitelisted
- Perform all integrity verification on cluster (admission controller, not in client side)
- Handle variations in application packaging and deployment (Helm /Operator /YAML / OLM Channel) with no modification in app installer

## Supported Platforms

Integrity Enforcer aims to provide a built-in mechanism for preventing integrity violation to resources on a cluster. IE currently supports the following platforms:

- ROKS
- RedHat OpenShift 4.3 (e.g. OCP on AWS)
- Minikube

## Prerequisites

The following prerequisites must be satisfied to deploy IE on a cluster.

- ROKS or RedHat OpenShift 4.3 cluster
- Admin access to the cluster to use `oc` command
- Three namespaces for IE. All resources for IE are deployed there. 
  - All IE resources are deployed in `integrity-enforcer` namespace.
  - Signatures are stored in `ie-sign` namespace. 
  - Policied are stored in `ie-policy` namespace. 
- All requests to namespaces with label `integrity-enforced=true` are processed by IE. 

## Setting up a key-ring secret
IE requires a key-ring secret to be available for enabling signature verification as part of integrity enforcement. See [here](operator/deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml)

```
    keyRingConfig:
    createIfNotExist: false
    keyValue: test
    name: keyring-secret
```
The following section shows how to setup a key-ring secret.

e.g. key-ring.yaml
```
apiVersion: v1
kind: Secret
metadata:
  name: keyring-secret
type: Opaque
data:
  keyring.gpg: <fill in encoded key ring>
```

Create key-ring secret in the namespace `integrity-enforce-ns` where `integrity-enforce` to be deployed
```
oc create -n integrity-enforce-ns -f key-ring.yaml
```

## Installation via CLI

This document describe steps for deploying Integrity Enforcer (IE) on your RedHat OpenShift cluster including ROKS via `oc` or `kubectl` CLI commands. 

First, clone this repository and moved to `integrity-enforcer` directory
```
git clone git@github.ibm.com:mutation-advisor/integrity-enforcer.git
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

    # Create secret for pulling images from IKS registry

    oc create -f deploy/mappregkey.yaml

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
