## How to Sign Resources

### Prerequisites

1. Generate GNUPG key (with your email address). E.g.: signer@enterprise.com
    ```
    gpg --full-generate-key
    ```

    Confirm if key is avaialble in keyring
    ```
    gpg -k signer@enterprise.com
    ```
2. Setup IE secret called `sig-verify-secret` (pubkey ring)

    IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.

    1. export key

        E.g. The following shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported as a key stored in `~/.gnupg/pubring.gpg`.
        ```
        $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
        $ cat ~/.gnupg/pubring.gpg | base64
        ```
    2.  embed encoded content of `~/.gnupg/pubring.gpg` to `sig-verify-secret` as follows:   

        E.g.:  /tmp/sig-verify-secret.yaml 
        ```
        apiVersion: v1
        kind: Secret
        metadata:
          name: sig-verify-secret
        type: Opaque
        data:
            pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
        ```

     3. create `sig-verify-secret` in namespace `IE_NS` in the cluster.
        ```
        $ oc create -f  /tmp/sig-verify-secret.yaml -n integrity-enforcer-ns
        ```      

### Generate a ResourceSignature

1. Specify a ConfigMap resource as follows 
    
    E.g. The following snippet (/tmp/single-rsc.yaml) shows a spec of a ConfigMap `sample-cm`

    ```
    apiVersion: v1
    kind: ConfigMap
    metadata:
        name: sample-cm
    data:
        key1: val1
        key2: val2
        key4: val4
    ```

2. Generate a ResourceSignature with the script: https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-rs-sign.sh

    Setup a signer in https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-sign-config.sh

    E.g. Configure `signer@enterprise.com` as SIGNER in the configuration file. 
    ```
    #!/bin/bash
    SIGNER=signer@enterprise.com
    ```

    Run the following script to generate a ResourceSignature which would be stored in a file `/tmp/single-rsc-rs.yaml`
    ```
    $ cd integrity-enforcer
    $ ./scripts/gpg-rs-sign.sh gpg-sign-config.sh /tmp/single-rsc.yaml /tmp/single-rsc-rs.yaml
    ```

2. Structure of generated ResourceSinature in `/tmp/single-rsc-rs.yaml`:
    
    ```
      apiVersion: research.ibm.com/v1alpha1
      kind: ResourceSignature
      metadata:
        annotations:
          messageScope: spec
          signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t ...
        name: rsig-sample-cm
      spec:
        data:
          - message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29u ...
            signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t ...
            type: resource
    ```
    
3. Message signed

    1. Single resource (`/tmp/single-rsc.yaml`)
        
        You can create a ResourceSignature for a single resource YAML file.
        Message signed is the entire content of the single resource file.

        E.g.:  A single resource is specifed in a YAML file, like below.
        ```
        apiVersion: v1
        kind: ConfigMap
        metadata:
            name: sample-cm
        data:
            key1: val1
            key2: val2
            key4: val4
        ```

    2. Muli resource (`/tmp/multi-rsc.yaml`)

        You can create a ResourceSignature for a multi resource YAML file.
        Message signed is the entire content of the multi resource file.

        E.g.:  Multiple resources are specifed in a YAML file, like below.
      
        ```
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: ie-sample-app
        spec:
          replicas: 2
          selector:
            matchLabels:
              app: ie-sample-app
          template:
            metadata:
              labels:
                app: ie-sample-app
            spec:
              containers:
              - name: ie-sample-app
                resources:
                  requests:
                    memory: "64Mi"
                    cpu: "250m"
                  limits:
                    memory: "128Mi"
                    cpu: "500m"
                image: docker.io/ie-sample-app:rc1
                ports:
                - containerPort: 80
              imagePullSecrets:
                - name: registry-secret

        ---
        apiVersion: v1
        kind: Service
        metadata:
          name: ie-sample-service
          labels:
            app: ie-sample-service
        spec:
          type: NodePort
          ports:
            - port: 80
          selector:
            app: ie-sample-app

        ---
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: ie-sampple-app-config
          labels:
            app: ie-sampple-app-config
        data:
          ie-app.properties: |
            message= This application has been signed.
        ```
    3. Helm release metadata yaml