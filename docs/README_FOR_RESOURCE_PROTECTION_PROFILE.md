## Define Protected Resources


### Create Resource Protection Profile
You can define which resources should be protected with signature in IE. For resources in a namespace, custom resource `ResourceProtectionProfile` (RPP) is created in the same namespace. The example below shows definition to protect `ConfigMap` and `Service` resource in `secure-ns` namespace. Only a RPP can be defined in each namespace.

    ```
    apiVersion: research.ibm.com/v1alpha1
    kind: ResourceProtectionProfile
    metadata:
      name: sample-rpp
      namespace: secure-ns
    spec:
      rules:
      - match:
        - kind: ConfigMap
        - kind: Service
    ```

If you are cluster-admin role, you can create these resource by 

```
oc apply -f sample-rpp.yaml -n secure-ns
```

This profile become effective in IE instantly for evaluating any further incoming admission requests. 

You can create these resource with valid signature even if you are not in cluster-admin role. It should be signed by a valid signer defined in the [Sign Policy](http://xxx). 
 
### Rule Syntax
You can list rules to define protect resources. 
Rule has `match` and `exclude` fields. 
The rules can be defined with the fields `namespace, name, operation, apiVersion, apiGroup, kind, username`. In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

If you want to exclude some resources from matched resources, you can set rules in `exclude` field.  

For example, the rule below covers any config map except name `unprotected-cm` and any resources in apiGroup `rbac.authorization.k8s.io` in the same namespace.

```
rules:
- match:
  - kind: ConfigMap
  exclude:
  - kind: ConfigMap
    name: unprotected-cm
- match:
  - apiGroup: rbac.authorization.k8s.io
```

Another example below is the rule below covers any resources in the same namespace.

```
  rules:
  - match:
    - kind: "*"
```

### Define allow patterns

The resources covered by the rule above cannot be created/updated without signature, but you may want to define cases for allowing requests in certain situations. 

You can use `ignoreServiceAccount` to define service accounts is allowed to request for matched resources. For example, any requests by `secure-operator` service account is allowed in in `secure-ns` 

### example
```
  ignoreServiceAccount:
  - match: 
      kind: "*"
    serviceAccountName:
    - system:serviceaccount:secure-ns:secure-operator
```

You can also set rules to allow some changes in the resource even without valid signature. For example, changes in attribute `data.comment1` in a config map `protected-cm` is allowed. 

```
  ignoreAttrs:
  - attrs:
    - data.comment1
    match:
      name: protected-cm
      kind: ConfigMap
```



### cluster scope
For cluster-scope resources, cluster scope custom resource `ClusterResourceProtectionProfile` (CRPP) are used. The example below shows definition to protect ClusterRoleBinding resource `sample-crb`.

```
apiVersion: research.ibm.com/v1alpha1
kind: ClusterResourceProtectionProfile
metadata:
  name: sample-crpp
spec:
rules:
- match:
    - kind: ClusterRoleBinding
    name: sample-crb
```

Rule syntax is same as RPP.

### Default RPP/CRPP

Cluster default RPP and CRPP are predefined in IE namespace. They are automatically created by IE operator when installing IE to the cluster. It is managed only by IE admin.

Default RPP/CRPP includes
- service accounts which are considered as platform operator.
- changes which is considered as expected normal platform behavior. 

### Delete/Disable RPP

RPP and CRPP has two lifecycle flags `disabled` and `delete`. Those fields are `false` by default. 

If `disabled` is set to `true`, the RPP (CRPP) become invalid and ignored (This implies no RPP is defined in the namespace). When you set `false` back, the RPP will become effective again. 

You cannot delete RPP or CRPP directly.
When you want to delete RPP, set `delete` to `true`, then IE will delete RPP (CRPP). 

```
apiVersion: research.ibm.com/v1alpha1
kind: ResourceProtectionProfile
metadata:
  name: sample-rpp
  namespace: secure-ns
spec:
  disabled: false
  delete: false
```

### Example of RPP

The whole RPP is represented like this. 
```
apiVersion: research.ibm.com/v1alpha1
kind: ResourceProtectionProfile
metadata:
  name: sample-rpp
  namespace: secure-ns
spec:
  disabled: false
  delete: false
  rules:
  - match:
    - kind: ConfigMap
    - kins: Secret
    exclude:
    - kind: ConfigMap
      name: unprotected-cm
  - match:
    - apiGroup: rbac.authorization.k8s.io
  ignoreServiceAccount:
  - match: 
      kind: "*"
    serviceAccountName:
    - system:serviceaccount:secure-ns:secure-operator
  ignoreAttrs:
  - match:
      name: protected-cm
      kind: ConfigMap
    attrs:
    - data.comment1
```
