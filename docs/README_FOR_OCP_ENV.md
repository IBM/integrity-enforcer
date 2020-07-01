# Integrity Enforcer (IE)

This document describe some tips for deploying and using IE on an OCP cluster.


## Create Namespace (if not exists)
  ```
   kubectl create ns integrity-enforcer-ns
  ```

## Deploy signing service and integrity-enforcer

See Documentation: [here](README_INSTALLATION_VIA_CLI.md)


## Prepare ES
The logs generated from IE can be forwarded to store in a ElasticSearch (ES). The following steps describe how to setup an ES service on OCP.

1. Deploy cluster logging on an OCP cluster

   Follow the steps in the following link:

   https://docs.openshift.com/container-platform/4.2/logging/cluster-logging-deploying.html

   Note: For step 5., create a cluster logging instance using the following yaml.
   For OCP on AWS, set `storageClassName: gp2`, for OCP on ROKS, set `storageClassName: ibmc-file-gold`

   ```
   apiVersion: "logging.openshift.io/v1"
   kind: "ClusterLogging"
   metadata:
     name: "instance" 
     namespace: "openshift-logging"
   spec:
     managementState: "Managed"  
     logStore:
       type: "elasticsearch"  
       elasticsearch:
         nodeCount: 1 
         storage:
           storageClassName: gp2 
           size: 500G
         redundancyPolicy: "ZeroRedundancy"
     visualization:
       type: "kibana"  
       kibana:
         replicas: 1
     curation:
       type: "curator"  
       curator:
         schedule: "30 3 * * *"
     collection:
       logs:
         type: "fluentd"  
         fluentd: {}
    ```

   Make sure Elasticsearch, kibana pods are running.


2. Copy ES secret to `integrity-enforcer-ns` namespace

   ```
   kubectl get secret elasticsearch -n openshift-logging  -o yaml \
   | sed s/"namespace: openshift-logging"/"namespace: integrity-enforcer-ns"/\
   | sed s/"name: elasticsearch"/"name:  es-tls-certs"/\
   | kubectl apply -n integrity-enforcer-ns -f -
   ```

   The above secret will be used by admission controller to push data to ES.

3.  Get the ES endpoint and specify in CR file for `integrity-enforcer`: `deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml`

    ```
    https://elasticsearch.openshift-logging.svc.cluster.local:9200
    ```

    The following snipet shows a portion of `deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml` where ES settings is configured:
    
    ```
    logger:
    enabled: true
    es:
      enabled: true
      host: https://elasticsearch.openshift-logging.svc.cluster.local:9200
      indexPrefix: ac-log
      port: 9200
      scheme: http
    esSecretName: es-tls-certs
    ```
   
## Prepare Chartmuseum

A Helm chart repository must exist to test any Helm based application package deployment with integrity enforcement. The following steps describe how to create a Helm chart repository called `Chartmuseum` on an OCP cluster.

1. Clone this repository  
   ```
    git clone git@github.ibm.com:mutation-advisor/integrity-enforcer.git
    cd integrity-enforcer/develop
   ```

2. Setup PesitantVolume (PV) in OCP

   Create PV in OCP dashboard:
   In Storage -> Persistent Volumes -> Create Persistent Volume (use gp2 storageClassname)
   For OCP on AWS, set `storageClassName: gp2`, for OCP on ROKS, set `storageClassName: ibmc-file-gold`
   
   ```
   apiVersion: v1
   kind: PersistentVolume
   metadata:
     name: chartmuseumpv
     labels:
       storage-tier: gold
   spec:
     capacity:
       storage: 5Gi
     accessModes:
       - ReadWriteOnce
     persistentVolumeReclaimPolicy: Recycle
     storageClassName: gp2
     nfs:
       path: /tmp
       server: 172.17.0.2
    ```

    Set a name for PV (e.g. chartmuseumpv)


3. Set security policy
   ```
   oc adm policy add-scc-to-user anyuid -z default
   ```
   
4. Install chartmuseum in OCP
   Note that PV setup in 2. is used in remote-chart-museum-config.yaml
   ```
   helm install chartmuseum stable/chartmuseum -f chartmuseum-setup/remote-chart-museum-config.yaml -n integrity-enforcer-ns
   ```

   Register private helm repo as chartmuseum (after portforwarding to private helm registry or setup a route in OCP dashboard)

   ```
   helm repo add chartmuseum http://localhost:8080
   ```

5. Add route in OCP to chartmuseum
   ```

   oc get route -n integrity-enforcer-ns
   NAME          HOST/PORT                                                                PATH   SERVICES                  PORT   TERMINATION   WILDCARD
   chartmuseum   chartmuseum-integrity-enforcer-ns.apps.ma4kdev3.openshiftv4test.com          chartmuseum-chartmuseum   http                 None

   ```

6. Push helm package to private helm repository

   ```
   curl -F "chart=@ac-test-chart-0.1.0.tgz" -F "prov=@ac-test-chart-0.1.0.tgz.prov" http://localhost:8080/api/charts
   ```


