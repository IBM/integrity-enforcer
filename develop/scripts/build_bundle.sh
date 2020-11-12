#!/bin/bash

cd $IE_REPO_ROOT/integrity-enforcer-operator

make bundle

make bundle-build BUNDLE_IMG=quay.io/gajananan/integrity-enforcer-operator-bundle:0.0.22dev


docker push quay.io/gajananan/integrity-enforcer-operator-bundle:0.0.22dev

sudo $GOPATH/bin/opm index add -c docker --generate --bundles quay.io/gajananan/integrity-enforcer-operator-bundle:0.0.22dev \
                      --from-index quay.io/gajananan/integrity-enforcer-operator-index:0.0.21dev \
                      --tag quay.io/gajananan/integrity-enforcer-operator-index:0.0.22dev --out-dockerfile tmp.Dockerfile

sudo rm tmp.Dockerfile

sudo docker build -f index.Dockerfile -t quay.io/gajananan/integrity-enforcer-operator-index:0.0.22dev --build-arg USER_ID=1001 --build-arg GROUP_ID=12009  . --no-cache

sudo docker push quay.io/gajananan/integrity-enforcer-operator-index:0.0.22dev

echo "Completed building bundle and index"
