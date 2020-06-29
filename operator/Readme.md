```
operator-sdk new integrity-enforcer-operator --repo=github.com/IBM/integrity-enforcer-operator
operator-sdk add api --api-version=research.ibm.com/v1alpha1 --kind=IntegrityEnforcer
operator-sdk generate k8s
operator-sdk generate crds
operator-sdk add controller --api-version=research.ibm.com/v1alpha1 --kind=IntegrityEnforcer
operator-sdk build integrityenforcer/integrity-enforcer-operator:dev
```

Compile integrity-enforcer-operator
```
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o build/_output/integrity-enforcer-operator ./cmd/manager
```

