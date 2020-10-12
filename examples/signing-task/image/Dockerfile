FROM registry.access.redhat.com/ubi7/ubi:latest AS build

RUN curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash &&\
    chmod +x ./kustomize &&\
    mv ./kustomize /usr/local/bin/kustomize

RUN curl -sSL https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -o /tmp/jq &&\
    chmod +x /tmp/jq &&\
    mv /tmp/jq /usr/local/bin/jq

RUN curl -LO https://github.com/mikefarah/yq/releases/download/3.3.2/yq_linux_amd64 &&\
    chmod +x yq_linux_amd64 &&\
    mv yq_linux_amd64 /usr/local/bin/yq

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.19.0/bin/linux/amd64/kubectl &&\
    chmod +x ./kubectl &&\
    mv ./kubectl /usr/local/bin/kubectl

RUN cat /etc/os-release

RUN yum repolist &&\
    yum update -y &&\
    yum install git -y && yum update git -y

RUN gpg --version
RUN git version


COPY generate_rpp.sh ./
COPY gpg-rs-sign.sh ./
