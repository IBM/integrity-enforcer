## Example: Tekton Signing Pipeline

This section describe the steps for integrating a sample IE signing task which could be integrated with a Tekton pipeline.

The sample signing task definition create signatures for YAML resources of a sample application hosted in a GitHub repository.


### Prerequisites for setting up the sample IE signing task in a Tekton pipeline definition.
- Resource for IE signing task.
 
   git clone this repository and moved to integrity-enforcer directory
   ```
   $ git clone https://github.com/IBM/integrity-enforcer.git
   $ cd integrity-enforcer
   $ pwd /home/repo/integrity-enforcer
   ```
   Content of signing task
   ```
   $ cd examples/signing-task   
   $ tree
    
	├── image
	│   ├── Dockerfile
	│   ├── Makefile
	│   ├── generate_rpp.sh
	│   └── gpg-rs-sign.sh
	└── yaml
	    └── ie-artifact-signing-task.yaml

   ```
   
   -  Prepare IE signing task container image
     1. `image` directory contains Docker file and scripts to generate IE signature resources.
     2.  Build the container image and push it a container registry which can be accessed by a target Tekton pipeline  

   -  Prepare IE signing Task as part of a Tekton pipeline
     1. `yaml` directory contains the IE signing task definition to be included in a Tekton pipeline.
     2.  Follow the following steps to prepare IE signing Task as part of a Tekton pipeline.

-  Prepare container image container IE signing scripts.

   - Setup container image name and tag in the Makefile.
     IE signing task deployed in a cluster would need to pull this container image and use it for signing artifacts.

   - Build a container image and push it to target container registry as follows.
     Note: Setup appropriate imagePullSecrets in the target pipline to pull this container image from target regsitry.

     ```
     $ cd integrity-enforcer/examples/signing-task/image
     $ make build   
     $ make push 
     ```
    

-  Prepare the IE signing task in a Tekton pipeline as follows
   - Copy `ie-artifact-signing-task.yaml` file to a directory where your Tekton pipeline definition exist.
   - In your pipeline definition, refer the IE signing task as shown below, by passing the required parameters.
  
     ```
     ---
	apiVersion: tekton.dev/v1alpha1
	kind: Pipeline
	metadata:
	  name: ie-ci-pipeline
	spec:
	  resources:
	  - name: cicd-git
	    type: git
	  params:
	  - name: signer-email
	    type: string
	    description: email of the artifact-signer
	  - name: cicd-git-url
	    type: string
	    description:   git repo url "e.g. https://github.com/sample-demo/sample-app.git"
	  - name: cicd-git-user-email
	    type: string
	    description: user email for git
	  - name: cicd-git-user-name
	    type: string
	    description: user name for git
	  tasks:
	  - name: ie-artifact-signing-task
	    taskRef:
	      name: ie-artifact-signing-task
	    params:
	      - name: source-branch
	        value: "main"
	      - name: dest-branch
	        value: "stage"
	      - name: signer-email
	        value: $(params.signer-email)
	      - name: git-repo-url
	        value: $(params.cicd-git-url)
	      - name: git-repo-user-email
	        value: $(params.cicd-git-user-email)
	      - name: git-repo-user-name
	        value: $(params.cicd-git-user-name)
	      - name: ignore-attrs
	        value: "true"
	    resources:
	      inputs:
	      - name: cicd
	        resource: cicd-git

      ---
      
      - IE signing task assumes the following parameters and input resources

        The following parameters need to be setup for using IE signing task as part of pipeline:
        -  signer-email:  email of the signer setup for signing YAML resources (refer: )
        -  git-repo-url: GitHub repository where the YAML resources of an application hosted
        -  git-repo-user-email: email of a user to access the GitHub repository where the YAML resources of an application hosted
        -  git-repo-user-name: email of a user to access the GitHub repository where the YAML resources of an application hosted
        -  source-branch:  A branch of a GitHub repository where the YAML resources of an application hosted
        -  dest-branch: A branch of a GitHub repository where the signatures and signed resources would be pushed by IE signing task.
        -  ignore-attrs: 

        The following input resource (type: Git) need to be defined for using IE signing task as part of pipeline:

        ```
         ---
        apiVersion: tekton.dev/v1alpha1
        kind: PipelineResource
        metadata:
          name: pipeline-resource-git
        spec:
          type: git
          params:
          - name: url
            value: https://github.com/sample-demo/sample-app
          - name: revision
            value: pre-stage
          - name: sslVerify
            value: "false"
        secrets:
          - fieldName: authToken
            secretName: git-secret
            secretKey: token

        ```
        The following secret need to be setup for integrating IE signing task as a part of pipeline. 
        IE signing task would access `git-secret` to retrive the token for accesing the target GitHub repository where YAML resources of a sample application is hosted.
     
        ```
        apiVersion: v1
	data:
	  token: MWE2OGY5MTc...  <Base64 encoding of a GitHub token of a user>
	kind: Secret
	metadata:
	  annotations:
	    tekton.dev/git-0: https://github.com
	  name: git-secret
	type: Opaque
        ```

