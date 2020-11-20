
FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

RUN mkdir /ie-op-app && mkdir /ie-op-app/resources

ADD /resources/default-rsp.yaml /ie-op-app/resources/default-rsp.yaml
ADD /resources/default-ie-cr.yaml /ie-op-app/resources/default-ie-cr.yaml
COPY build/_output/bin/integrity-verifier-operator /ie-op-app/manager

RUN chgrp -R 0 /ie-op-app && chmod -R g=u /ie-op-app

WORKDIR /ie-op-app

ENTRYPOINT ["/ie-op-app/manager"]
