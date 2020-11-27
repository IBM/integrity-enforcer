# Development

## Clone Repo
```
$ git clone git@github.com:IBM/integrity-enforcer.git
$ cd integrity-verifier
```

## Setup
Before executing the script, setup local environment as follows:

- `IV_REPO_ROOT`: set absolute path of the root directory of cloned integrity-verifier source repository
- `KUBECONFIG=~/kube/config/minikube`  (for deploying IV on minikube cluster)

`~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

For example
```
$ export KUBECONFIG=~/kube/config/minikube
$ export IV_REPO_ROOT=/repo/integrity-enforcer
```

## Make commands∂


### Build
```
$ make build-images
```

Three images are built.
- `integrity-verifier-operator` is image for operator which manages Integrity Verifier
- `integrity-verifier-server` is image for IV server
- `integrity-verifier-logging` is image for IV logging side car

### Push images
```
$ make push-images
```

You may need to setup image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed.

For example
```
$ export DOCKER_REGISTRY=docker.io
$ export DOCKER_USER=integrityverifier
$ export DOCKER_PASS=<password>
```

### Install IV to cluster
```
$ cd integrity-verifier
$ make install-crds
$ make install-operator
$ make setup-tmp-cr
$ make create-tmp-cr
```

This script includes the steps for
- Create CRDs
- Install Integrity Verifier operator
- Prepare Integrity Verifier custom resource (operator installs IV server automatically)
- Install Integrity Verifier custom resource (operator installs IV server automatically)

### Uninstall IV from cluster
```
$ make delete-tmp-cr
$ make delete-operator
$ make delete-crds
```

This script includes the steps for
- Delete Integrity Verifier custom resource (operator installs IV server automatically)
- Delete Integrity Verifier operator
- Delete CRDs

