# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This repo is build in Travis-ci by default;
# Override this variable in local env.
TRAVIS_BUILD ?= 1

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
#IMG ?= $(shell cat COMPONENT_NAME 2> /dev/null)
#VERSION ?= $(shell cat COMPONENT_VERSION 2> /dev/null)

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
DEST ?= $(GOPATH)/src/$(GIT_HOST)/$(BASE_DIR)


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

ifeq ($(IE_REPO_ROOT),)
$(error IE_REPO_ROOT is not set)
endif

include  .env
export $(shell sed 's/=.*//' .env)

ifeq ($(ENV_CONFIG),)
$(error ENV_CONFIG is not set)
endif

include  $(ENV_CONFIG)
export $(shell sed 's/=.*//' $(ENV_CONFIG))

.PHONY: config int fmt lint test coverage build build-images


config:
	@[ "${ENV_CONFIG}" ] && echo "Env config is all good" || ( echo "ENV_CONFIG is not set"; exit 1 )


############################################################
# format section
############################################################

# All available format: format-go format-protos format-python
# Default value will run all formats, override these make target with your requirements:
#    eg: fmt: format-go format-protos
fmt: format-go


format-go:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | grep -v 'vendor/' | grep -v 'third_party/' | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

############################################################
# check section
############################################################

check: lint

# All available linters: lint-dockerfiles lint-scripts lint-yaml lint-copyright-banner lint-go lint-python lint-helm lint-markdown lint-sass lint-typescript lint-protos
# Default value will run all linters, override these make target with your requirements:
#    eg: lint: lint-go lint-yaml
lint: lint-init  lint-verify lint-op-init lint-op-verify

lint-init:
	cd $(ENFORCER_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck > lint_results.txt

lint-verify:
	$(eval FAILURES=$(shell cat $(ENFORCER_DIR)lint_results.txt | grep "FAIL:"))
	cat $(ENFORCER_DIR)lint_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)

lint-op-init:
	cd $(ENFORCER_OP_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck,govet > lint_results.txt

lint-op-verify:
	$(eval FAILURES=$(shell cat $(ENFORCER_OP_DIR)lint_results.txt | grep "FAIL:"))
	cat $(ENFORCER_OP_DIR)lint_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)


############################################################
# images section
############################################################

build-images:
	./develop/scripts/build_images.sh


push-images:
	./develop/scripts/push_images.sh

############################################################
# bundle section
############################################################

build-bundle:
	- ./develop/scripts/build_bundle.sh

############################################################
# clean section
############################################################
clean::

############################################################
# check copyright section
############################################################
copyright-check:
	./build/copyright-check.sh $(TRAVIS_BRANCH)

############################################################
# unit test section
############################################################

test-unit: test-init-try test-init test-verify

test-init-try:
	cd $(ENFORCER_DIR) &&  go test -v  $(shell cd $(ENFORCER_DIR) && go list ./... | grep -v /vendor/ | grep -v /pkg/util/kubeutil)

test-init:
	cd $(ENFORCER_DIR) &&  go test -v  $(shell cd $(ENFORCER_DIR) && go list ./... | grep -v /vendor/ | grep -v /pkg/util/kubeutil) > results.txt
test-verify:
	$(eval FAILURES=$(shell cat $(ENFORCER_DIR)results.txt | grep "FAIL:"))
	cat $(ENFORCER_DIR)results.txt
	@$(if $(strip $(FAILURES)), echo "One or more unit tests failed. Failures: $(FAILURES)"; exit 1, echo "All unit tests passed successfully."; exit 0)


############################################################
# e2e test section
############################################################
.PHONY: kind-bootstrap-cluster
kind-bootstrap-cluster: kind-create-cluster install-crds install-resources

.PHONY: kind-bootstrap-cluster-dev
kind-bootstrap-cluster-dev: kind-create-cluster install-crds install-resources

#check-env:
#ifndef DOCKER_USER
#	$(error DOCKER_USER is undefined)
#endif
#ifndef DOCKER_PASS
#	$(error DOCKER_PASS is undefined)
#endif

#kind-deploy-controller: check-env
#	@echo installing config policy controller

test-e2e: kind-create-cluster install-crds install-resources setup-cr e2e-test delete-resources kind-delete-cluster

kind-create-cluster:
	@echo "creating cluster"
	kind create cluster --name test-managed
	kind get kubeconfig --name test-managed > $(ENFORCER_OP_DIR)kubeconfig_managed

kind-delete-cluster:
	@echo deleting cluster
	kind delete cluster --name test-managed

install-crds:
	@echo installing crds
	kustomize build $(ENFORCER_OP_DIR)config/crd | kubectl apply -f -

delete-crds:
	@echo deleting crds
	kustomize build $(ENFORCER_OP_DIR)config/crd | kubectl delete -f -

install-resources:
	@echo
	@echo creating namespaces
	kubectl create ns $(IE_OP_NS)
	@echo creating keyring-secret
	kubectl create -f $(ENFORCER_OP_DIR)test/deploy/keyring_secret.yaml -n $(IE_OP_NS)
	@echo setting image
	cd $(ENFORCER_OP_DIR)config/manager && kustomize edit set image controller=$(IE_OPERATOR_IMAGE_NAME_AND_VERSION)
	@echo installing operator
	kustomize build $(ENFORCER_OP_DIR)config/default | kubectl apply --validate=false -f -

delete-resources:
	@echo
	@echo deleting keyring-secret
	kubectl delete -f $(ENFORCER_OP_DIR)test/deploy/keyring_secret.yaml -n $(IE_OP_NS)
	@echo deleting operator
	kustomize build $(ENFORCER_OP_DIR)config/default | kubectl delete -f -

setup-cr:
	@echo
	@echo prepare cr
	@echo copy cr into test dir
	cp $(ENFORCER_OP_DIR)config/samples/apis_v1alpha1_integrityenforcer.yaml $(ENFORCER_OP_DIR)test/deploy
	@echo insert image
	yq write -i $(ENFORCER_OP_DIR)test/deploy/apis_v1alpha1_integrityenforcer.yaml spec.logger.image $(IE_LOGGING_IMAGE_NAME_AND_VERSION)
	yq write -i $(ENFORCER_OP_DIR)test/deploy/apis_v1alpha1_integrityenforcer.yaml spec.server.image $(IE_ENFORCER_IMAGE_NAME_AND_VERSION)

e2e-test:
	@echo
	@echo run test
	$(shell cd $(ENFORCER_OP_DIR) && go test -v ./test/e2e -coverprofile cover.out > $(ENFORCER_OP_DIR)e2e_results.txt)
	$(eval FAILURES=$(shell cat e2e_results.txt | grep "FAIL:"))
	cat $(ENFORCER_OP_DIR)e2e_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more e2e tests failed. Failures: $(FAILURES)"; exit 1, echo "All e2e tests passed successfully."; exit 0)

############################################################
# e2e test coverage
############################################################
#build-instrumented:
#	go test -covermode=atomic -coverpkg=github.com/open-cluster-management/$(IMG)... -c -tags e2e ./cmd/manager -o build/_output/bin/$(IMG)-instrumented

#run-instrumented:
#	WATCH_NAMESPACE="managed" ./build/_output/bin/$(IMG)-instrumented -test.run "^TestRunMain$$" -test.coverprofile=coverage_e2e.out &>/dev/null &

#stop-instrumented:
#	ps -ef | grep 'config-po' | grep -v grep | awk '{print $$2}' | xargs kill

#coverage-merge:
#	@echo merging the coverage report
#	gocovmerge $(PWD)/coverage_* >> coverage.out
#	cat coverage.out
