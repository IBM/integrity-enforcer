
FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

RUN mkdir /iv-op-app && mkdir /iv-op-app/resources

ADD /resources/default-rsp.yaml /iv-op-app/resources/default-rsp.yaml
ADD /resources/default-iv-cr.yaml /iv-op-app/resources/default-iv-cr.yaml
COPY build/_output/bin/integrity-verifier-operator /iv-op-app/manager

RUN chgrp -R 0 /iv-op-app && chmod -R g=u /iv-op-app

WORKDIR /iv-op-app

ENTRYPOINT ["/iv-op-app/manager"]
