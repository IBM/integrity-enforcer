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

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.1

RUN microdnf install -y curl git git-lfs tar && microdnf clean all

RUN git lfs install

COPY install.sh /tmp/install.sh
RUN /tmp/install.sh

ENV ENVTEST_ASSETS_DIR /usr/local/kubebuilder/
COPY setup-envtest.sh $ENVTEST_ASSETS_DIR/setup-envtest.sh
RUN mkdir -p ENVTEST_ASSETS_DIR && source $ENVTEST_ASSETS_DIR/setup-envtest.sh; fetch_envtest_tools $ENVTEST_ASSETS_DIR; setup_envtest_env $ENVTEST_ASSETS_DIR

RUN mkdir -p /ishield-app && mkdir -p /ishield-app/public

COPY build/_bin/argocd-builder-core /usr/local/bin/argocd-builder-core
COPY replace-image.sh /tmp/replace-image.sh

RUN chgrp -R 0 /ishield-app && chmod -R g=u /ishield-app

WORKDIR /ishield-app

ENTRYPOINT ["argocd-builder-core"]


