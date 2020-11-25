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

# LOAD ENVIRNOMENT SETTINGS (must be done at first)
###########################
ifeq ($(IV_REPO_ROOT),)
$(error IV_REPO_ROOT is not set)
endif

include  .env
export $(shell sed 's/=.*//' .env)

ifeq ($(ENV_CONFIG),)
$(error ENV_CONFIG is not set)
endif

include  $(ENV_CONFIG)
export $(shell sed 's/=.*//' $(ENV_CONFIG))

include $(VERIFIER_OP_DIR)Makefile


# CICD BUILD HARNESS
####################
ifeq ($(UPSTREAM_ENV),true)
  USE_VENDORIZED_BUILD_HARNESS = false
else
  USE_VENDORIZED_BUILD_HARNESS ?=
endif


ifndef USE_VENDORIZED_BUILD_HARNESS
-include $(shell curl -s -H 'Authorization: token ${GITHUB_TOKEN}' -H 'Accept: application/vnd.github.v4.raw' -L https://api.github.com/repos/open-cluster-management/build-harness-extensions/contents/templates/Makefile.build-harness-bootstrap -o .build-harness-bootstrap; echo .build-harness-bootstrap)
else
#-include vbh/.build-harness-bootstrap
-include $(shell curl -sSL -o .build-harness "https://git.io/build-harness"; echo .build-harness)
endif
####################

.PHONY: default
default::
	@echo "Build Harness Bootstrapped"

# Docker build flags
DOCKER_BUILD_FLAGS := --build-arg VCS_REF=$(GIT_COMMIT) $(DOCKER_BUILD_FLAGS)

# This repo is build in Travis-ci by default;
# Override this variable in local env.
TRAVIS_BUILD ?= 1

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
	cd $(VERIFIER_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck > /tmp/lint_results.txt

lint-verify:
	$(eval FAILURES=$(shell cat /tmp/lint_results.txt | grep "FAIL:"))
	/tmp/lint_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)

lint-op-init:
	cd $(VERIFIER_OP_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck,govet > lint_results.txt

lint-op-verify:
	$(eval FAILURES=$(shell cat $(VERIFIER_OP_DIR)lint_results.txt | grep "FAIL:"))
	cat $(VERIFIER_OP_DIR)lint_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)


############################################################
# images section
############################################################

build-images:
		$(IV_REPO_ROOT)/build/build_images.sh

docker-login:
		${IV_REPO_ROOT}/build/docker_login.sh

push-images: docker-login
		${IV_REPO_ROOT}/build/push_images.sh

pull-images:
		${IV_REPO_ROOT}/build/pull_images.sh

############################################################
# bundle section
############################################################
.ONESHELL:
build-bundle:
		if [ ${UPSTREAM_ENV} = true ]; then
			if [ -z "${QUAY_REGISTRY}" ]; then
				echo "QUAY_REGISTRY is empty."
				exit 1;
			fi
			if [ -z "${QUAY_USER}" ]; then
				echo "QUAY_USER is empty."
				exit 1;
			fi
			if [ -z "${QUAY_PASS}" ]; then
				echo "QUAY_PASS is empty."
				exit 1;
			fi
			docker login ${QUAY_REGISTRY} -u ${QUAY_USER} -p ${QUAY_PASS}
			$(IV_REPO_ROOT)/build/build_bundle.sh
		else
			$(IV_REPO_ROOT)/build/build_bundle_ocm.sh
		fi

############################################################
# clean section
############################################################
clean::

############################################################
# check copyright section
############################################################
copyright-check:
	 - $(IV_REPO_ROOT)/build/copyright-check.sh $(TRAVIS_BRANCH)

############################################################
# unit test section
############################################################

test-unit: test-init test-verify

test-init:
	cd $(VERIFIER_DIR) &&  go test -v  $(shell cd $(VERIFIER_DIR) && go list ./... | grep -v /vendor/ | grep -v /pkg/util/kubeutil | grep -v /pkg/util/sign/pgp) > /tmp/results.txt

test-verify:
	$(eval FAILURES=$(shell cat /tmp/results.txt | grep "FAIL:"))
	cat /tmp/results.txt
	@$(if $(strip $(FAILURES)), echo "One or more unit tests failed. Failures: $(FAILURES)"; exit 1, echo "All unit tests passed successfully."; exit 0)


############################################################
# e2e test section
############################################################
.PHONY: kind-bootstrap-cluster
kind-bootstrap-cluster: kind-create-cluster install-crds install-resources

.PHONY: kind-bootstrap-cluster-dev
kind-bootstrap-cluster-dev: kind-create-cluster install-crds install-resources

TEST_SIGNERS=TestSigner
TEST_SIGNER_SUBJECT_EMAIL=signer@enterprise.com
TEST_SECRET=keyring_secret

test-e2e: create-kind-cluster setup-image install-crds setup-iv-env install-resources setup-cr setup-test-resources setup-test-env e2e-test delete-test-env delete-keyring-secret delete-resources delete-kind-cluster clean-test-resources

test-e2e-no-init: push-images-to-local setup-iv-env install-crds install-resources setup-cr setup-test-env setup-test-resources e2e-test clean-test-resources

create-kind-cluster:
	@echo "creating cluster"
	# kind create cluster --name test-managed
	bash $(VERIFIER_OP_DIR)test/create-kind-cluster.sh
	kind get kubeconfig --name test-managed > $(VERIFIER_OP_DIR)kubeconfig_managed

delete-kind-cluster:
	@echo deleting cluster
	kind delete cluster --name test-managed

install-crds:
	@echo installing crds
	kustomize build $(VERIFIER_OP_DIR)config/crd | kubectl apply -f -

delete-crds:
	@echo deleting crds
	kustomize build $(VERIFIER_OP_DIR)config/crd | kubectl delete -f -

setup-iv-env:
	@echo
	@echo creating namespaces
	kubectl create ns $(IV_OP_NS)
	@echo creating keyring-secret
	kubectl create -f $(VERIFIER_OP_DIR)test/deploy/keyring_secret.yaml -n $(IV_OP_NS)

delete-keyring-secret:
	@echo
	@echo deleting keyring-secret
	kubectl delete -f $(VERIFIER_OP_DIR)test/deploy/keyring_secret.yaml -n $(IV_OP_NS)

install-resources:
	@echo
	@echo setting image
	cp $(VERIFIER_OP_DIR)config/manager/kustomization.yaml /tmp/kustomization.yaml  #copy original file to tmp dir.
	cd $(VERIFIER_OP_DIR)config/manager && kustomize edit set image controller=$(IV_LOCAL_OPERATOR_IMAGE_NAME_AND_VERSION)
	@echo installing operator
	kustomize build $(VERIFIER_OP_DIR)config/default | kubectl apply --validate=false -f -
	cp /tmp/kustomization.yaml $(VERIFIER_OP_DIR)config/manager/kustomization.yaml  #put back the original file from tmp dir.

delete-resources:
	@echo
	@echo deleting operator
	kustomize build $(VERIFIER_OP_DIR)config/default | kubectl delete -f -

setup-image: pull-images push-images-to-local

push-images-to-local:
	@echo push image into local registry
	docker tag $(IV_SERVER_IMAGE_NAME_AND_VERSION) $(IV_LOCAL_SERVER_IMAGE_NAME_AND_VERSION)
	docker tag $(IV_LOGGING_IMAGE_NAME_AND_VERSION) $(IV_LOCAL_LOGGING_IMAGE_NAME_AND_VERSION)
	docker tag $(IV_OPERATOR_IMAGE_NAME_AND_VERSION) $(IV_LOCAL_OPERATOR_IMAGE_NAME_AND_VERSION)
	docker push $(IV_LOCAL_SERVER_IMAGE_NAME_AND_VERSION)
	docker push $(IV_LOCAL_LOGGING_IMAGE_NAME_AND_VERSION)
	docker push $(IV_LOCAL_OPERATOR_IMAGE_NAME_AND_VERSION)

TMP_CR_FILE=/tmp/apis_v1alpha1_integrityverifier.yaml
TMP_CR_UPDATED_FILE=/tmp/apis_v1alpha1_integrityverifier_update.yaml

setup-cr:
	@echo
	@echo prepare cr
	@echo copy cr into tmp dir
	cp $(VERIFIER_OP_DIR)config/samples/apis_v1alpha1_integrityverifier_local.yaml $(TMP_CR_FILE)
	@echo insert image
	yq write -i $(TMP_CR_FILE) spec.logger.image $(IV_LOCAL_LOGGING_IMAGE_NAME_AND_VERSION)
	yq write -i $(TMP_CR_FILE) spec.server.image $(IV_LOCAL_SERVER_IMAGE_NAME_AND_VERSION)
	@echo setup signer policy
	yq write -i $(TMP_CR_FILE) spec.signPolicy.policies[2].namespaces[0] $(TEST_NS)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.policies[2].signers[0] $(TEST_SIGNERS)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.signers[1].name $(TEST_SIGNERS)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.signers[1].secret $(TEST_SECRET)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.signers[1].subjects[0].email $(TEST_SIGNER_SUBJECT_EMAIL)


setup-test-env:
	@echo
	@echo creating test namespace
	kubectl create ns $(TEST_NS)

delete-test-env:
	@echo
	@echo deleting test namespace
	kubectl delete ns $(TEST_NS)

setup-test-resources:
	@echo
	@echo prepare cr for updating test
	cp $(TMP_CR_FILE) $(TMP_CR_UPDATED_FILE)
	yq write -i $(TMP_CR_UPDATED_FILE) spec.signPolicy.signers[1].subjects[1].email test@enterprise.com

clean-test-resources:
	rm $(TMP_CR_FILE)
	rm $(TMP_CR_UPDATED_FILE)

e2e-test:
	@echo
	@echo run test
	$(IV_REPO_ROOT)/build/check_test_results.sh



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
