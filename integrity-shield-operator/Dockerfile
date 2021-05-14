
FROM registry.access.redhat.com/ubi7/ubi-minimal:7.8

RUN mkdir /ishield-op-app && mkdir /ishield-op-app/resources && \
    curl -L https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o jq-linux64 && \
    chmod +x jq-linux64 && \
    mv jq-linux64 /usr/local/bin/jq

ADD /scripts /ishield-op-app/scripts
ADD /resources/common-profiles /ishield-op-app/resources/common-profiles
ADD /resources/default-ishield-cr.yaml /ishield-op-app/resources/default-ishield-cr.yaml
ADD /resources/webhook-rules-for-roks.yaml /ishield-op-app/resources/webhook-rules-for-roks.yaml
COPY build/_output/bin/integrity-shield-operator /ishield-op-app/manager

RUN chgrp -R 0 /ishield-op-app && chmod -R g=u /ishield-op-app

WORKDIR /ishield-op-app

ENTRYPOINT ["/ishield-op-app/manager"]
