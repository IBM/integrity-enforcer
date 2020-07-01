# Integrity Enforcer (IE)

This document describe some tips for deploying and using IE on a minikube cluster.


## Install minikube  
   Get installer from https://kubernetes.io/docs/tasks/tools/install-minikube/


## Start a minikube service  
   ```
   $ minikube start --kubernetes-version='v1.15.0'
   ```

   - about `--kubernetes-version='v1.15.0'`  
   In kubernetes v1.16.0 and later, "apiVersion" for a lot of resources has changed. The current yamls are based on v1.15.0 version.  

   |Kind |apiVersion (v1.15.0) |apiVersion(v1.16.0) |
   |---|---|---|
   |deployment |extensions/v1beta1 | apps|
   |podsecuritypolicy    |extensions/v1beta1| policy|


   `minikube start` takes a while.
   if it has correctly started, you can see something like the below.

   ```
   $ kubectl get node
   NAME       STATUS   ROLES    AGE     VERSION
   minikube   Ready    master   3m19s   v1.15.0
   ```

   ```
   $ kubectl get ns
   NAME              STATUS   AGE
   default           Active   3m31s
   kube-node-lease   Active   3m34s
   kube-public       Active   3m34s
   kube-system       Active   3m34s
   ```

## Create a Namespace (if not exists)

   ```
    kubectl create ns integrity-enforcer-ns
   ```

## Deploy signing service and integrity-enforcer

See Documentation: [here](README_INSTALLATION_VIA_CLI.md)

## Prepare Chartmuseum (same namespace as integrity-enforcer)

A Helm chart repository must exist to test any Helm based application package deployment with integrity enforcement. The following steps describe how to create a Helm chart repository called `Chartmuseum` on a minikube cluster.

1. Create a PesistantVolume (pv) in minikube
   ``` 
   oc create -n integrity-enforcer-ns -f pv.yaml

   ```
   
   Content of pv.yaml:
   ```
   apiVersion: v1
   kind: PersistentVolume
   metadata:
     name: chartmuseumpv
   spec:
     capacity:
       storage: 1Gi
     accessModes:
       - ReadWriteOnce
     persistentVolumeReclaimPolicy: Recycle
     hostPath:
       path: /data/pv0001/
   ```
   Set a name for PV (e.g. chartmuseumpv)
 
2. Clone this repository
  ```
   git clone https://github.com/IBM/integrity-enforcer.git
   cd integrity-enforcer/delveop
  ``` 

3. Install chartmuseum repository in `ieenforce` namespace

   Note that PV setup created in 1. is referenced in the `local-chart-museum-config.yaml`

   ```
   helm install chartmuseum stable/chartmuseum -f chartmuseum-setup/local-chart-museum-config.yaml -n integrity-enforcer-ns
   ```

   Register private helm repo as chartmuseum (after portforwarding to private helm registry or setup a service in minikube)

   ```
   helm repo add chartmuseum http://localhost:8080
   ```

