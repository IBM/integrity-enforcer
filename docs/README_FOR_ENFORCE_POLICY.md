# EnforcePolicy
EnforcePolicy includes the following fields: 
- __enforce__ 
- __ignoreRequest__ 
- __allowedSigner__
- __allowedForInternalRequest__
- __allowedByRule__
- __allowedChange__
- __permitIfVerifiedOwner__
- __permitIfFirstUser__.

## enforce

You can select which request is subject to enforcement.  
`enforce` includes these fields:
```
namespace, name, operation, apiVersion, kind, username, type, k8screatedby, usergroup
```

In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

### example #1
```
    enforce:
    - namespace: secure-ns, test-ns
```

### example #2
```
    enforce:
    - namespace: '*'
```


## ignoreRequest
You can decide rules to ignore request.The applicable request is not applied any enforcer's process and no log is output.  

ignoreRequest includes these fields:

```
namespace, name, operation, apiVersion, kind, username, type, k8screatedby, usergroup
```
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.  

### example
```
    ignoreRequest:
    - kind: Event
    - kind: Lease
```


## allowedSigner
allowedSigner rule has `subject` and `request` fields.

### request
Request has `name`, `operation`, `namespace` and `kind` field.  
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

### subject
You can set signer by `commonName`

### example
```
    allowedSigner:
    - request:
        namespace: secure-ns
      subject:
        commonName: Service Team Admin A
```

## allowedForInternalRequest
The requests initiated by k8s platform should be listed here.
allowedForInternalRequest includes these fields:

```
namespace, name, operation, apiVersion, kind, username, type, k8screatedby, usergroup
```
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

### example
```
    allowedForInternalRequest:
    - kind: Secret
      operation: CREATE
      type: kubernetes.io/service-account-token
      username: system:kube-controller-manager
```


## allowedByRule
You can set rule to allow request.
allowedByRule includes these field:

```
namespace, name, operation, apiVersion, kind, username, type, k8screatedby, usergroup
```

In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard. 

### example
```
   allowedByRule: []
```

## allowedChange
You can set rules to allow update request.  
allowedChange rule has three fields, `key`, `owner` and `request`.

### key
The listed keys are allowed to change.   
"__*__" can be used as a wildcard.

### owner
Owner has `kind`, `apiVersion` and `name` field.  
If the owner of the updated resource matches with the owner in the policy, the allowedChange rule is applied.  
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

### request
Request has `username`, `kind`, `name`, `namespace` and `usergroup` field.  
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

### example
```
    allowedChange:
    - key:
      - data.comment1
      owner: 
        kind: 'TestChart'
        apiVersion: 'charts.helm.k8s.io/v1alpha1'
        name: 'test-app1'
      request:
        username: IAM#app_owner@enterprise.com
        kind: ConfigMap
        name: test-app1-test-chart-cm
        namespace: *
```


## permitIfVerifiedOwner
The request is allowed if the requested resource has verified owner and the request meet the permitIfVerifiedOwner condition.
the is allowed to be changed.
permitIfVerifiedOwner includes these fields:  

```
namespace, name, operation, apiVersion, kind, username, type, k8screatedby, usergroup
```

In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.  

### example
```
    permitIfVerifiedOwner:
    - namespace: '*'
```


## permitIfFirstUser
The request is allowed if the service account is the same as it was when the resource was created, and the request meet the `permitIfFirstUser` condition.  
`permitIfFirstUser` includes these fields.  

```
namespace, name, operation, apiVersion, kind, username, type, k8screatedby, usergroup
```
In each field, values can be listed with "__,__" and "__*__" can be used as a wildcard.

### example
```
    permitIfFirstUser: []
```


