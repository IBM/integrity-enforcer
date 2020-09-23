## Generate Resource Signature

1. Generate a ResourceSignature with the script: https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-rs-sign.sh

    Setup a signer in https://github.ibm.com/mutation-advisor/ciso-css-sign/blob/master/gpg-sign-config.sh

    ```
    #!/bin/bash
    SIGNER=signer@enterprise.com
    ```

    Run the following script to generate a ResourceSignature
    ```
    $ ./scripts/gpg-rs-sign.sh gpg-sign-config.sh /tmp/single-rsc.yaml /tmp/single-rsc-rs.yaml
    ```

2. Structure of generated ResourceSinature `test-cm-rs.yaml`:
    
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
    
3. Message signed
    1. Single resource (`single-rsc.yaml`)
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

    2. Muli resource (`multi-rsc.yaml`)

    3. Helm release metadata yaml