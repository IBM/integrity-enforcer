## Tekton Signing Pipeline

### Prerequisites
-  Install Tekton in the cluser, in which Tekton pipeline would run
   E.g.: See [How to install Tekton on OpenShift](https://docs.openshift.com/container-platform/4.5/pipelines/installing-pipelines.html#installing-pipelines)

-  Setup a sample application Git repository
   
    
### Setup a sample Tekton signing pipline 

This pipeline would sign resources cloned from  a sample application repository and deploy them to a cluster protected by `integrity-enforcer`

This section describe steps for deploying and running a Tekton pipeline in an OpenShift cluster to sign resources of an application to be deployed in a target cluster.

The sample pipeline would pull sources of an application from a specified Git repository and sign YAML files in the cloned repository and deploy them to a target cluster protected by `integrity-enforcer-ns`

1. Create a namespace `artifact-signing-ns` in a cluster where the pipeline would run. The sample pipeline would be deployed in this namespace.

2. Create a Secret resource called `registry-secret` in namespace `artifact-signing-ns` to pull container images required to run the pipeline from a container registry
   
   E.g. A registry secret (registry-secret.yaml) is shown below:

   ```
    apiVersion: v1
    kind: Secret
    metadata:
        name: registry-secret
    type: kubernetes.io/dockerconfigjson
    data:
      .dockerconfigjson:  eyJhdXRocyI6eyJ1cy5pY3IuaW8iOnsidXNlcm5hbWUiOiJpYW ...
   ```

3. Specify a Secret resource called `kubeconfig-secret` in namespace `artifact-signing-ns` to access the target cluster where the application should be deployed.

   Get the encoded content of kubeconfig for the target cluster
   ```
   $ oc config view --minify=true | base64
   ```
   
   Embed it in `kubeconfig-secret.yaml`.
   E.g. A kubeconfig-secret (kubeconfig-secret.yaml) is shown below:
    ```   
    apiVersion: v1
    kind: Secret
    metadata:
       name: kubeconfig-secret
    type: Opaque
    data:
      kubeconfig: YXBpVmVyc2lvbjogdjEKY2x1c3RlcnM6
    ```
   
4. Specify a Secret resource called `git-credentials` in namespace `artifact-signing-ns` to access the target Git repository where the application is hosted. 
 
    E.g.: A git-credentials (git-credentials.yaml) is shown below
    ```
    apiVersion: v1
    kind: Secret
    metadata:
       name: git-credentials
    type: Opaque
    data:
       username: Z2FqYW5....
       password: OTA1NmYwZTY...
    ```


5. Deploy Pipeline resources in the cluster
   
   ```
   $ cd develop/signing-pipeline/tekton-pipeline
   $ oc create -f admin-role.yaml -n artifact-signing-ns
   $ oc create -f registry-secret.yaml -n artifact-signing-ns
   $ oc create -f git-credentials.yaml -n artifact-signing-ns
   $ oc create -f kubeconfig-secret.yaml -n artifact-signing-ns
   $ oc create -f pipeline.yaml -n artifact-signing-ns
   $ oc create -f task-clone-repo.yaml -n artifact-signing-ns
   $ oc create -f task-sign-repo.yaml -n artifact-signing-ns
   $ oc create -f openshift-pvc.yaml -n artifact-signing-ns
   ```

5. Run the Signing pipline as follows:

    In the target cluster, in which the sample application to be deployed,  create a namespace `sample-app-ns`  (if not exist).

    ```
    $ tkn pipeline start pipeline-ie \
        -p pipeline-pvc="pipeline-pvc" \
        -p git-url="...." \
        -p git-branch="master" \
        -p git-username="....." \
        -p git-token="9056f0e68d89888de9fffbbd8f759f74d2cc3fcf" \
        -p signer-email="signer@enterprise.com"\
        -p deploy-namespace="sample-app-ns" \
        -s ie-signing-pipline-admin                                                                                                                                       
     ```

     Check the list of pipelineruns
     ```
     $ tkn pipelinerun list
      NAME                    STARTED          DURATION     STATUS
      pipeline-ie-run-jllw7   9 minutes ago    24 seconds   Succeeded
     ```

     Check the logs of pipelinerun to see if it successfully completed
     ```
     $ tkn pipelinerun logs pipeline-ie-run-jllw7 -f -n artifact-signing-ns

     ```