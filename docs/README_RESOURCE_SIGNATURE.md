## How to Sign Resources

### Define a public key for verifying signature by IE.

IE requires a secret that includes a pubkey ring for verifying signatures of resources that need to be protected.  IE supports X509 or PGP key for signing resources. We describe signing resources using PGP key as follows.

1. If you do not have a PGP key, generate PGP key as shown below.
   
    Use your `name` and `email` to generate PGP key using the following command
    ```
    $ gpg --full-generate-key
    ```

    Confirm if key is avaialble in keyring. The following example shows a PGP key is successfully generated using email `signer@enterprise.com`
    ```
      $ gpg -k signer@enterprise.com
      gpg: checking the trustdb
      gpg: marginals needed: 3  completes needed: 1  trust model: pgp
      gpg: depth: 0  valid:   2  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 2u
      pub   rsa3072 2020-09-24 [SC]
             FE866F3F88FCDAF42BB1B1ED23EC90D3DAD9A6C0
      uid           [ultimate] signer@enterprise.com <signer@enterprise.com>
      sub   rsa3072 2020-09-24 [E]
    ```
2. Once you have a PGP key, export it as a file.

    The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `~/.gnupg/pubring.gpg`.

    ```
    $ gpg --export signer@enterprise.com > ~/.gnupg/pubring.gpg
    ```

3. Define a secret that includes a pubkey ring for verifying signatures of resources

   The encoded content of `~/.gnupg/pubring.gpg` can be retrived by using the following command:
    ```
    $ cat ~/.gnupg/pubring.gpg | base64
    ```

    Once you have the encoded content of `~/.gnupg/pubring.gpg`, embed it to `/tmp/sig-verify-secret.yaml` as follows.

    ```
      apiVersion: v1
      kind: Secret
      metadata:
          name: sig-verify-secret
      type: Opaque
      data:
            pubring.gpg: mQGNBF5nKwIBDADIiSiWZkD713UWpg2JBPomrj/iJRiMh ...
    ```
4. Create Secret resource `sig-verify-secret` in a namespace `integrity-enforcer-ns` in the cluster.

    Run the following command to create the secret
    ```
    $ oc create -f  /tmp/sig-verify-secret.yaml -n integrity-enforcer-ns
    ```

---


### Generate signature for a resource

1. Specify a ConfigMap resource 
    
    E.g. The following snippet (/tmp/single-rsc.yaml) shows a spec of a ConfigMap `test-cm`

    ```
    apiVersion: v1
    kind: ConfigMap
    metadata:
        name: test-cm
    data:
        key1: val1
        key2: val2
        key4: val4
    ```


2. Try to create ConfigMap resource `test-cm` shown above (/tmp/single-rsc.yaml) in the namespace `secure-ns`, before creating a signature.

    Run the command below to create ConfigMap `test-cm`, but it fails because no signature for this resource is stored in the cluster.

    ```
    $ oc create -f /tmp/single-rsc.yaml -n secure-ns
    Error from server: error when creating "single-rsc.yaml": admission webhook "ac-server.integrity-enforcer-ns.svc" denied the request: No signature found
    ```

3. Generate a signature for a resource 

    To generate a signature for a resource,  we use a utility [script](https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-rs-sign.sh)

    We setup a signer in the [config file](https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-sign-config.sh)

    The following shows the content of config file: `gpg-sign-config.sh`  which configures `signer@enterprise.com` as `SIGNER`.

    ```
    #!/bin/bash
    SIGNER=signer@enterprise.com
    ```

    Run the following script to generate a signature
      - `gpg-sign-config.sh`:  Config file to specify a signer
      - `/tmp/single-rsc.yaml`:  A resource file to be signed, which may include specification for a single resource or multiple resources
      - `/tmp/single-rsc-rs.yaml`: A custom resource `ResourceSignature` generated that includes signature for the resource

    ```
    $ ./scripts/gpg-rs-sign.sh gpg-sign-config.sh /tmp/single-rsc.yaml /tmp/single-rsc-rs.yaml
    ```

    Generated signature for a resource is included in a custom resource `ResourceSignature`.

    Structure of generated `ResourceSinature` in `/tmp/single-rsc-rs.yaml`:
    
    ```
      apiVersion: research.ibm.com/v1alpha1
      kind: ResourceSignature
      metadata:
        annotations:
          messageScope: spec
          signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t ...
        name: rsig-test-cm
      spec:
        data:
          - message: YXBpVmVyc2lvbjogdjEKa2luZDogQ29u ...
            signature: LS0tLS1CRUdJTiBQR1AgU0lHTkFUVVJFLS0t ...
            type: resource
    ```
    
4. Store the generated signature in a cluster.
    
    After creating the ResourceSignature in a cluster, the corresponding resource can be created successfully after successfull signature verification by IE.
    
    ```
    $ oc create -f /tmp/single-rsc-rs.yaml -n integrity-enforcer-ns
    resourcesignature.research.ibm.com/rsig-test-cm created
    ```

5. Create a resource in a specific namespace after creating the signature in the cluster.

    Run the command below to create a ConfigMap resource (/tmp/single-rsc.yaml), it should be successful this time because a corresponding ResourceSignature is available in the cluster.
    ```
    $ oc create -f /tmp/single-rsc.yaml -n secure-ns
    configmap/test-cm created
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
            name: test-cm
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