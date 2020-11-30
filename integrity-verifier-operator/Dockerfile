
FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

RUN mkdir /iv-op-app && mkdir /iv-op-app/resources

# install `shadow-utils` for `adduser` package
RUN microdnf install -y shadow-utils
RUN adduser -u 1000 ivuser

RUN chgrp -R 1000 /iv-op-app && chmod -R g=u /iv-op-app

ADD /resources/default-rsp.yaml /iv-op-app/resources/default-rsp.yaml
ADD /resources/default-iv-cr.yaml /iv-op-app/resources/default-iv-cr.yaml
COPY build/_output/bin/integrity-verifier-operator /iv-op-app/manager

WORKDIR /iv-op-app

USER 1000

ENTRYPOINT ["/iv-op-app/manager"]
