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

# Specify whether this repo is build locally or not, default values is '1';
# If set to 1, then you need to also set 'DOCKER_USERNAME' and 'DOCKER_PASSWORD'
# environment variables before build the repo.
BUILD_LOCALLY ?= 1

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
# IBMDEV Set image and repo
IMAGE_NAME ?= integrity-enforcer-operator
IMAGE_REPO ?= integrityenforcer
CSV_VERSION_LOCAL ?= 0.0.3
CSV_VERSION ?= 0.0.3
IMAGE_LOCAL ?="$(IMAGE_NAME):$(CSV_VERSION_LOCAL)"
IMAGE_REMOTE ?="$(IMAGE_REPO)/$(IMAGE_NAME):$(CSV_VERSION)"

# The namespcethat operator will be deployed in
#IE_NS ?= ie-operator

# Github host to use for checking the source tree;
# Override this variable ue with your own value if you're working on forked repo.
GIT_HOST ?= github.com/IBM

PWD := $(shell pwd)
BASE_DIR := $(shell basename $(PWD))

# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
GOBIN_DEFAULT := $(GOPATH)/bin
export GOBIN ?= $(GOBIN_DEFAULT)
TESTARGS_DEFAULT := "-v"
export TESTARGS ?= $(TESTARGS_DEFAULT)
DEST := $(GOPATH)/src/$(GIT_HOST)/$(BASE_DIR)
VERSION ?= $(shell git describe --exact-match 2> /dev/null || \
                 git describe --match=$(git rev-parse --short=8 HEAD) --always --dirty --abbrev=8)

LOCAL_OS := $(shell uname)
ifeq ($(LOCAL_OS),Linux)
    TARGET_OS ?= linux
    XARGS_FLAGS="-r"
else ifeq ($(LOCAL_OS),Darwin)
    TARGET_OS ?= darwin
    XARGS_FLAGS=
else
    $(error "This system's OS $(LOCAL_OS) isn't recognized/supported")
endif

ARCH := $(shell uname -m)
LOCAL_ARCH := "amd64"
ifeq ($(ARCH),x86_64)
    LOCAL_ARCH="amd64"
else ifeq ($(ARCH),ppc64le)
    LOCAL_ARCH="ppc64le"
else ifeq ($(ARCH),s390x)
    LOCAL_ARCH="s390x"
else
    $(error "This system's ARCH $(ARCH) isn't recognized/supported")
endif

############################################################
# work section
############################################################
$(GOBIN):
	@echo "create gobin"
	@mkdir -p $(GOBIN)

work: $(GOBIN)

############################################################
# format section
############################################################

# All available format: format-go format-python
# Default value will run all formats, override these make target with your requirements:
#    eg: fmt: format-go format-protos
fmt: format-go format-python

############################################################
# check section
############################################################

# check: lint

# All available linters: lint-dockerfiles lint-scripts lint-yaml lint-copyright-banner lint-go lint-python lint-helm lint-markdown
# Default value will run all linters, override these make target with your requirements:
#    eg: lint: lint-go lint-yaml
# The MARKDOWN_LINT_WHITELIST variable can be set with comma separated urls you want to whitelist
# lint: lint-all

############################################################
# test section
############################################################

test:
	@go test ${TESTARGS} ./...

############################################################
# coverage section
############################################################

coverage:
	@scripts/codecov.sh ${BUILD_LOCALLY}

############################################################
# install operator sdk section
############################################################

install-operator-sdk:
	@operator-sdk version 2> /dev/null ; if [ $$? -ne 0 ]; then ./scripts/install-operator-sdk.sh; fi

############################################################
# build section
############################################################

build: build-amd64 build-ppc64le build-s390x

build-amd64:
	@echo "Building the ${IMAGE_NAME} amd64 binary..."
	@GOARCH=amd64 scripts/gobuild.sh build/_output/bin/$(IMAGE_NAME) ./cmd/manager

build-ppc64le:
	@echo "Building the ${IMAGE_NAME} ppc64le binary..."
	@GOARCH=ppc64le scripts/gobuild.sh build/_output/bin/$(IMAGE_NAME)-ppc64le ./cmd/manager

build-s390x:
	@echo "Building the ${IMAGE_NAME} s390x binary..."
	@GOARCH=s390x scripts/gobuild.sh build/_output/bin/$(IMAGE_NAME)-s390x ./cmd/manager


############################################################
# clean section
############################################################
clean:
	@rm -rf build/_output

.PHONY: all work fmt coverage test build image images multiarch-image clean

############################################################
# install section
############################################################

build-operator-image:
			docker build -f  build/Dockerfile -t $(IMAGE_LOCAL) .

push-operator-image: build-operator-image
			docker tag $(IMAGE_LOCAL) $(IMAGE_REMOTE)
			docker push $(IMAGE_REMOTE)

deploy-operator: check-env
		kubectl create -f deploy/service_account.yaml -n $(IE_NS)
		kubectl create -f deploy/role.yaml -n $(IE_NS)
		cat deploy/role_binding.yaml | yq w - subjects[0].namespace $(IE_NS) | kubectl create -f - -n $(IE_NS)
		kubectl create -f deploy/$(OPERATOR_YAML) -n $(IE_NS)


delete-operator: check-env
		kubectl delete -f deploy/service_account.yaml -n $(IE_NS)
		kubectl delete -f deploy/role.yaml -n $(IE_NS)
		kubectl delete -f deploy/role_binding.yaml -n $(IE_NS)
		kubectl delete -f deploy/$(OPERATOR_YAML) -n $(IE_NS)


create-cr: check-env
		cat deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml \
                       | yq w - spec.namespace $(IE_NS) | kubectl create -f - -n $(IE_NS)


delete-cr: check-env
		kubectl delete -f deploy/crds/research.ibm.com_v1alpha1_integrityenforcer_cr.yaml -n $(IE_NS)



deploy: build-amd64 push-operator-image deploy-operator

delete: delete-operator


init:
	kubectl create -f deploy/crds/research.ibm.com_integrityenforcers_crd.yaml

init-delete:
	kubectl delete -f deploy/crds/research.ibm.com_integrityenforcers_crd.yaml

get-all: check-env
	kubectl get all -n $(IE_NS)

log-events: check-env check-ie-server
	kubectl logs -f -n $(IE_NS) $(IE_SERVER_POD) -c forwarder | grep --line-buffered ' fw.events: ' | awk '{sub(/^.* fw.events: /, "", $$0);print $0;fflush()}' | jq --unbuffered -r '. | [.namespace, .allowed, .kind, .name, .operation, .userName, .["sig.signer.email"], .msg] | @tsv'

log-raw-events: check-env check-ie-server
	kubectl logs -f -n $(IE_NS) $(IE_SERVER_POD) -c forwarder | grep --line-buffered ' fw.events: ' | awk '{sub(/^.* fw.events: /, "", $$0);print $0;fflush()}' | jq --unbuffered .

log-server: check-env check-ie-server
	kubectl logs -f -n $(IE_NS) $(IE_SERVER_POD) -c server 

log-forwarder: check-env check-ie-server
	kubectl logs -f -n $(IE_NS) $(IE_SERVER_POD) -c forwarder 

log-operator: check-env check-ie-operator
	kubectl logs -f -n $(IE_NS) $(IE_OPERATOR_POD)

log-ss: check-env check-signservice
	kubectl logs -f -n $(IE_NS) $(SIGN_SERVICE_POD)

get-cr: check-env check-ie-server
	kubectl get integrityenforcers.research.ibm.com $(IE_SERVER_CR) -n $(IE_NS) -o yaml 

edit-cr: check-env check-ie-server
	kubectl edit integrityenforcers.research.ibm.com $(IE_SERVER_CR) -n $(IE_NS)

get-policy: check-env check-policy
	kubectl get enforcepolicies.research.ibm.com $(IE_POLICY_CR) -n $(IE_NS) -o yaml 

edit-policy: check-env check-policy
	kubectl edit enforcepolicies.research.ibm.com $(IE_POLICY_CR) -n $(IE_NS)

check-env:
ifndef IE_NS
	$(error IE_NS is undefined)
endif

ifndef IE_ENV
	$(error IE_ENV is undefined)
endif

ifeq ($(IE_ENV),roks)
$(eval OPERATOR_YAML := operator.yaml)
endif

ifeq ($(IE_ENV),remote)
$(eval OPERATOR_YAML := operator.yaml)
endif

ifeq ($(IE_ENV),local)
$(eval OPERATOR_YAML := ../develop/local-deploy/operator_local.yaml)
endif


ifndef OPERATOR_YAML
$(error IE_ENV must be set from "roks", "remote" or "local")
endif

check-ie-operator:
	$(eval IE_OPERATOR_POD := $(shell kubectl get pod -n $(IE_NS) | grep Running | grep integrity-enforcer-operator- | awk '{print $$1}'))

check-ie-server:
	$(eval IE_SERVER_POD := $(shell kubectl get pod -n $(IE_NS) | grep Running | grep integrity-enforcer-server- | awk '{print $$1}'))
	$(eval IE_SERVER_CR := $(shell kubectl get integrityenforcers.research.ibm.com -n $(IE_NS) | head -n 2 | tail -n 1 | awk '{print $$1}'))

check-signservice:
	$(eval SIGN_SERVICE_POD := $(shell kubectl get pod -n $(IE_NS) | grep Running | grep signservice- | awk '{print $$1}'))

check-policy:
	$(eval IE_POLICY_CR := $(shell kubectl get enforcepolicies.research.ibm.com -n $(IE_NS) | head -n 2 | tail -n 1 | awk '{print $$1}'))

.PHONY: build-operator-image push-operator-image deploy-operator delete-operator create-cr delete-cr
