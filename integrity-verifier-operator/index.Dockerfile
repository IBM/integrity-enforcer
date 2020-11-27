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

FROM quay.io/operator-framework/upstream-opm-builder AS builder

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

RUN microdnf update && microdnf clean all &&\
    microdnf install -y --nodocs shadow-utils hostname

ARG USER_ID=1001
ARG GROUP_ID=12009

ENV USER opmuser
RUN groupadd -g ${GROUP_ID} ${USER} &&\
    useradd -g ${USER} -u ${USER_ID} -m ${USER} &&\
    usermod -aG wheel ${USER}


USER ${USER}
RUN whoami

LABEL operators.operatorframework.io.index.database.v1=/work/index.db

COPY --chown=opmuser:opmuser ["nsswitch.conf", "/etc/nsswitch.conf"]
COPY --chown=opmuser:opmuser ["database", "/work"]
COPY --chown=opmuser:opmuser  --from=builder /bin/opm /bin/opm
COPY --chown=opmuser:opmuser --from=builder /bin/grpc_health_probe /bin/grpc_health_probe

RUN chown  opmuser:opmuser /work/index.db &&\
    chown  opmuser:opmuser /bin/opm &&\
    chown  opmuser:opmuser /bin/grpc_health_probe &&\
    chown  opmuser:opmuser /etc/nsswitch.conf
  

EXPOSE 50051
USER 1001
WORKDIR /work

ENTRYPOINT ["/bin/opm"]
CMD ["registry", "serve", "--database", "index.db"]
