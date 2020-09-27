# How to Sign Resources

## Sign Type

x509, pgp

## verification key


## utility script to sign resources


## Helm support




6. Message signed
    
    `ResourceSignature` resource has a `message` field which refers to the encoded content of a resource file to be signed.  A resource file may include a specification for single resource (e.g. `/tmp/single-rsc.yaml`) or multiple resources (e.g. `/tmp/multi-rsc.yaml`).

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

        The encoded content of `/tmp/single-rsc.yaml` can be retrived by using the following command:
        ```
        $ cat /tmp/single-rsc.yaml | base64
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

        The encoded content of `/tmp/multi-rsc.yaml` can be retrived by using the following command:
        ```
        $ cat /tmp/multi-rsc.yaml | base64
        ```
        
    3. Helm release metadata yaml