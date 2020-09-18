# ResourceProtectionProfile

This document describes how to set up ResourceProtectionProfile (RPP).

RPP includes the following fields: 
- __disabled__ 
- __delete__ 
- __rules__
- __ignoreServiceAccount__
- __unprotectAttrs__
- __protectAttrs__
- __ignoreAttrs__
____

## rules
You can list rules to define protect resources. Rule has `match` and `exclude` fields. 
If you want to exclude some resources from matched resources, you can set rules in `exclude` field.  
The rules can be defined with the following fields. In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

```
namespace, name, operation, apiVersion, apiGroup, kind, username,
```

### example #1
```
  rules:
  - match:
    - namespace: secure-ns
      kind: ConfigMap
    exclude:
    - namespace: secure-ns
      kind: ConfigMap
      name: unprotected-cm
  - match:
    - namespace: secure-ns
      apiGroup: rbac.authorization.k8s.io
```

### example #2
```
  rules:
  - match:
    - namespace: secure-ns
      kind: "*"
```

____

## ignoreServiceAccount
The request is allowed if the username is defined in `serviceAccountName` field.

### example
```
  ignoreServiceAccount:
  - match: 
      kind: "*"
    serviceAccountName:
    - system:serviceaccount:secure-ns:secure-operator
```
____
## protectAttrs

## unprotectAttrs
____

## ignoreAttrs
You can set rules to allow some changes in the resource.

### example
```
  ignoreAttrs:
  - attrs:
    - data.comment1
    match:
      name: protected-cm
      kind: ConfigMap
```
____


## disabled
This field is `false` by default.
____

## delete
This field is `false` by default.

____


## ResourceProtectionProfile example

```
apiVersion: research.ibm.com/v1alpha1
kind: ResourceProtectionProfile
metadata:
  name: sample-rpp
spec:
  rules:
  - match:
    - namespace: secure-ns
      kind: ConfigMap, Secret
    exclude:
    - namespace: secure-ns
      kind: ConfigMap
      name: unprotected-cm
  - match:
    - namespace: secure-ns
      apiGroup: rbac.authorization.k8s.io
  ignoreServiceAccount:
  - match: 
      kind: "*"
    serviceAccountName:
    - system:serviceaccount:secure-ns:secure-operator
  ignoreAttrs:
  - attrs:
    - data.comment1
    match:
      name: protected-cm
      kind: ConfigMap
```