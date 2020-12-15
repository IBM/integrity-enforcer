# Development

## Clone Repo
```
$ git clone git@github.com:IBM/integrity-enforcer.git
$ cd integrity-shield
```

## Setup
Before executing the script, setup local environment as follows:

- `ISHIELD_REPO_ROOT`: set absolute path of the root directory of cloned integrity-shield source repository
- `KUBECONFIG=~/kube/config/minikube`  (for deploying IShield on minikube cluster)

`~/kube/config/minikube` is the Kuebernetes config file with credentials for accessing a cluster via `kubectl`.

For example
```
$ export KUBECONFIG=~/kube/config/minikube
$ export ISHIELD_REPO_ROOT=/repo/integrity-enforcer
```

## Make commands


### Build
```
$ make build-images
$ make tag-images-to-local
```

The make commands refer the steps for
- Building Integrity Shield container images
- Tagging Integrity Shield container images to be used locally.

Three images are built.
- `integrity-shield-operator` is image for operator which manages Integrity Shield
- `integrity-shield-server` is image for IShield server
- `integrity-shield-logging` is image for IShield logging side car

### Push images
```
$ make push-images
```

You may need to setup image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed.

For example
```
$ export DOCKER_REGISTRY=docker.io
$ export DOCKER_USER=integrityshield
$ export DOCKER_PASS=<password>
```

### Install IShield to cluster
```
$ make install-crds
$ make install-operator
$ make setup-tmp-cr
$ make create-tmp-cr
```

The make commands refer the steps for
- Create CRDs
- Install Integrity Shield operator
- Prepare Integrity Shield custom resource (operator installs IShield server automatically)
- Install Integrity Shield custom resource (operator installs IShield server automatically)

### Uninstall IShield from cluster
```
$ make delete-tmp-cr
$ make delete-operator
```

The make command refers to the steps for
- Delete Integrity Shield custom resource (operator installs IShield server automatically)
- Delete Integrity Shield operator
- Delete CRDs

