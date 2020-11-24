# Development

## Clone Repo
```
$ git clone git@github.com:IBM/integrity-enforcer.git
$ cd integrity-verifier
```

## Setup
Before executing the script, setup local environment as follows:
- `IV_ENV`: set `remote` for deploying IV on OpenShift or ROKS clusters. (use [guide](README_DEPLOY_IV_LOCAL.md) for deploying IV in minikube)
- `IV_NS`: set a namespace where IV to be deployed (use `integrity-verifier-ns` in this doc)
- `IV_REPO_ROOT`: set absolute path of the root directory of cloned integrity-verifier source repository

For example
```
$ export IV_ENV=remote
$ export IV_NS=integrity-verifier-ns
$ export IV_REPO_ROOT=/repo/integrity-enforcer
```

## Scripts


### Build
```
$ ./develop/scripts/build_images.sh
```

Three images are built.
- `integrity-verifier-operator` is image for operator which manages Integrity Verifier
- `iv-server` is image for IV server
- `iv-logging` is image for IV logging side car

### Push images
```
$ ./develop/scripts/push_images.sh
```

You may need to setup image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed

### Install IV to cluster
```
$ ./scripts/install_verifier.sh
```

This script includes the steps for
- Create CRDs
- Install Integrity Verifier operator
- Install Integrity Verifier custom resource (operator installs IV server automatically)

### Uninstall IV from cluster
```
$ ./scripts/delete_verifier.sh
```

This script includes the steps for
- Delete Integrity Verifier custom resource (operator installs IV server automatically)
- Delete Integrity Verifier operator
- Delete CRDs

