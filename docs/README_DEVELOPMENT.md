# Development

## Clone Repo
```
$ git clone git@github.ibm.com:mutation-advisor/integrity-enforcer.git
$ cd integrity-enforcer
```

## Setup
Before executing the script, setup local environment as follows:
- `IE_ENV`: set `remote` for deploying IE on OpenShift or ROKS clusters. (use [guide](README_DEPLOY_IE_LOCAL.md) for deploying IE in minikube)
- `IE_NS`: set a namespace where IE to be deployed (use `integrity-enforcer-ns` in this doc)
- `IE_REPO_ROOT`: set absolute path of the root directory of cloned integrity-enforcer source repository

For example
```
$ export IE_ENV=remote
$ export IE_NS=integrity-enforcer-ns
$ export IE_REPO_ROOT=/repo/integrity-enforcer
```

## Scripts


### Build
```
$ ./develop/scripts/build_images.sh
```

Three images are built.
- `integrity-enforcer-operator` is image for operator which manages Integrity Enforcer
- `ie-server` is image for IE server
- `ie-logging` is image for IE logging side car

### Push images
```
$ ./develop/scripts/push_images.sh
```

You may need to setup image registry (e.g. dockerhub, quay.io etc.) and change the container images' name and tag as needed

### Install IE to cluster
```
$ ./scripts/install_enforcer.sh
```

This script includes the steps for
- Create CRDs
- Install Integrity Enforcer operator
- Install Integrity Enforcer custom resource (operator installs IE server automatically)

### Uninstall IE from cluster
```
$ ./scripts/delete_enforcer.sh
```

This script includes the steps for
- Delete Integrity Enforcer custom resource (operator installs IE server automatically)
- Delete Integrity Enforcer operator
- Delete CRDs

