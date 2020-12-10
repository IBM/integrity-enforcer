
FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

RUN mkdir /ishield-op-app && mkdir /ishield-op-app/resources

ADD /resources/default-rsp.yaml /ishield-op-app/resources/default-rsp.yaml
ADD /resources/default-ishield-cr.yaml /ishield-op-app/resources/default-ishield-cr.yaml
COPY build/_output/bin/integrity-shield-operator /ishield-op-app/manager

RUN chgrp -R 0 /ishield-op-app && chmod -R g=u /ishield-op-app

WORKDIR /ishield-op-app

ENTRYPOINT ["/ishield-op-app/manager"]
