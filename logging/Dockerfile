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


FROM registry.access.redhat.com/ubi7/ubi-minimal:latest

USER root

RUN REPOLIST=ubi-7,ubi-7-rhscl,ubi-7-rhah,ubi-7-optional,ubi-7-server-beta-rpms,ubi-7-server-extras-rpms,ubi-7-server-optional-rpms,ubi-server-rhscl-7-rpms \
    INSTALL_PACKAGES="system-logos openssl-devel zlib-devel gcc make git bzip2 rh-ruby25-ruby rh-ruby25-ruby-devel rh-ruby25-rubygems rh-ruby25-rubygems-devel rh-ruby25 hostname shadow-utils" && \
    microdnf -y update && \
    microdnf -y install --setopt=tsflags=nodocs ${INSTALL_PACKAGES} && \
    microdnf clean all

RUN scl enable rh-ruby25 bash
ENV PATH /opt/rh/rh-ruby25/root/bin/:$PATH
RUN echo "/opt/rh/rh-ruby25/root/usr/lib64" >> /etc/ld.so.conf.d/rh-ruby.conf && \
    ldconfig && \
    gem install bundle


ENV PATH /opt/rh/rh-ruby25/root/usr/local/bin/:$PATH

WORKDIR /tmp
COPY Gemfile Gemfile
COPY Gemfile.lock Gemfile.lock

RUN bundle update --bundler &&\
    bundle install

ENV PATH /opt/rh/rh-ruby25/root/usr/share/gems/gems/fluentd-1.6.3/bin/:$PATH

ENV USER ac-app
RUN groupadd -g 12009 ${USER} &&\
    useradd -l -g ${USER} -u 1000190000 -m ${USER} &&\
    mkdir /ac-app

ADD src/ /ac-app/
RUN chown -R ${USER}:${USER} /ac-app/ &&\
    chmod -R 766 /ac-app/



USER ${USER}

WORKDIR /ac-app
ENTRYPOINT ["bash", "entrypoint.sh"]
