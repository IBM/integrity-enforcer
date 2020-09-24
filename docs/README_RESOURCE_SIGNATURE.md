## How to Sign Resources

### Define a public key for verifying signature by IE.

   
1. Generate GNUPG key (with your email address). 
   
    E.g.: signer@enterprise.com
    ```
    gpg --full-generate-key
    ```

    Confirm if key is avaialble in keyring
    ```
    gpg -k signer@enterprise.com
    ```
2. Define a public key for verifying signature by IE.
   
    IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.

    1. export key

        E.g. The following shows a pubkey for a signer identified by an email `signer@enterprise.com` 
        
        Export pbkey and store it in `~/.gnupg/pubring.gpg`.
        ```
        $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
        $ cat ~/.gnupg/pubring.gpg | base64
        ```
    2.  embed encoded content of `~/.gnupg/pubring.gpg` to `/tmp/sig-verify-secret.yaml` as follows:   

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

     3. create secret `sig-verify-secret` in namespace `integrity-enforcer-ns` in the cluster.
        ```
        $ oc create -f  /tmp/sig-verify-secret.yaml -n integrity-enforcer-ns
        ```      

---

### Generate signature for a resource to be protected in a namespace

1. Specify a ConfigMap resource to be protected 
    
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

2. Generate a signature for a resource with the script: https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-rs-sign.sh

    Setup a signer in https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-sign-config.sh

    E.g. Configure `signer@enterprise.com` as `SIGNER` in the configuration file. 
    ```
    #!/bin/bash
    SIGNER=signer@enterprise.com
    ```

    Run the following script to generate a signature which would be stored in a file `/tmp/single-rsc-rs.yaml` (`ResourceSignature`)
    ```
    $ cd integrity-enforcer
    $ ./scripts/gpg-rs-sign.sh gpg-sign-config.sh /tmp/single-rsc.yaml /tmp/single-rsc-rs.yaml
    ```

3. Generated signature for a resource is included in a custom resource `ResourceSignature`
    
    Structure of generated `ResourceSinature` in `/tmp/single-rsc-rs.yaml`:

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
    
4. Message signed
    
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