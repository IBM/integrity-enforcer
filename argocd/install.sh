#!/bin/bash

#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -eux -o pipefail

ARCHITECTURE=amd64
DOWNLOADS=/tmp/dl
BIN=/usr/local/bin
KUSTOMIZE_VERSION=4.1.2
HELM_VERSION=3.5.1
HELM2_VERSION=2.17.0
KSONNET_VERSION=0.13.1

# prepare download dir
mkdir -p $DOWNLOADS


# install kustomize
echo "Installing kustomize command..."
kustomize_target_file=kustomize_${KUSTOMIZE_VERSION}_linux_${ARCHITECTURE}.tar.gz
kustomize_url=https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_$ARCHITECTURE.tar.gz
curl -sLf --retry 3 -o ${DOWNLOADS}/${kustomize_target_file} "${kustomize_url}"
tar -C /tmp -xf ${DOWNLOADS}/${kustomize_target_file}
install -m 0755 /tmp/kustomize $BIN/kustomize
echo "done."

# install helm
echo "Installing helm command..."
helm_target_file=helm-v${HELM_VERSION}-linux-${ARCHITECTURE}.tar.gz
curl -sLf --retry 3 -o $DOWNLOADS/${helm_target_file} https://get.helm.sh/helm-v${HELM_VERSION}-linux-$ARCHITECTURE.tar.gz
mkdir -p /tmp/helm && tar -C /tmp/helm -xf $DOWNLOADS/${helm_target_file}
install -m 0755 /tmp/helm/linux-$ARCHITECTURE/helm $BIN/helm
echo "done."

# install helm2
echo "Installing helm2 command..."
helm2_target_file=helm-v${HELM2_VERSION}-linux-${ARCHITECTURE}.tar.gz
curl -sLf --retry 3 -o ${DOWNLOADS}/${helm2_target_file} https://storage.googleapis.com/kubernetes-helm/helm-v${HELM2_VERSION}-linux-$ARCHITECTURE.tar.gz
mkdir -p /tmp/helm2 && tar -C /tmp/helm2 -xf $DOWNLOADS/${helm2_target_file}
install -m 0755 /tmp/helm2/linux-$ARCHITECTURE/helm $BIN/helm2
echo "done."

# install ksonnet
echo "Installing ksonnet command..."
ksonnet_target_file=ks_${KSONNET_VERSION}_linux_${ARCHITECTURE}.tar.gz
curl -sLf --retry 3 -o $DOWNLOADS/${ksonnet_target_file} https://github.com/ksonnet/ksonnet/releases/download/v${KSONNET_VERSION}/ks_${KSONNET_VERSION}_linux_${ARCHITECTURE}.tar.gz
tar -C /tmp -xf $DOWNLOADS/${ksonnet_target_file}
install -m 0755 /tmp/ks_${KSONNET_VERSION}_linux_${ARCHITECTURE}/ks $BIN/ks
echo "done."