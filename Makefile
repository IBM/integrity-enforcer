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

# LOAD ENVIRNOMENT SETTINGS (must be done at first)
###########################
ifeq ($(ISHIELD_REPO_ROOT),)
$(error ISHIELD_REPO_ROOT is not set)
endif
ifeq ($(ISHIELD_ENV),)
$(error "ISHIELD_ENV is empty. Please set local or remote.")
endif

include  .env
export $(shell sed 's/=.*//' .env)

ifeq ($(ENV_CONFIG),)
$(error ENV_CONFIG is not set)
endif

include  $(ENV_CONFIG)
export $(shell sed 's/=.*//' $(ENV_CONFIG))

include $(SHIELD_OP_DIR)Makefile

ifeq ($(ISHIELD_TEMP_DIR),)
TMP_DIR = /tmp/
else
TMP_DIR = $(ISHIELD_TEMP_DIR)
$(shell mkdir -p $(TMP_DIR))
endif

# CICD BUILD HARNESS
####################
ifeq ($(ISHIELD_ENV), remote)
-include $(shell curl -s -H 'Authorization: token ${GITHUB_TOKEN}' -H 'Accept: application/vnd.github.v4.raw' -L https://api.github.com/repos/open-cluster-management/build-harness-extensions/contents/templates/Makefile.build-harness-bootstrap -o .build-harness-bootstrap; echo .build-harness-bootstrap)
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
SHIELD_BASE_DIR=$(TRAVIS_BUILD_DIR)/shield
SHIELD_OP_BASE_DIR=$(TRAVIS_BUILD_DIR)/integrity-shield-operator

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
	cd $(SHIELD_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck > $(TMP_DIR)lint_results_ishield.txt

lint-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results_ishield.txt | grep "FAIL:"))
	cat  $(TMP_DIR)lint_results_ishield.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)

lint-op-init:
	cd $(SHIELD_OP_DIR) && golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck,govet > $(TMP_DIR)lint_results.txt

lint-op-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results.txt | grep "FAIL:"))
	cat $(TMP_DIR)lint_results.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)


############################################################
# images section
############################################################

build-images:
		@if [ -z "$(NO_CACHE)" ]; then \
			$(ISHIELD_REPO_ROOT)/build/build_images.sh false; \
		else \
			$(ISHIELD_REPO_ROOT)/build/build_images.sh $(NO_CACHE); \
		fi


push-images:
		${ISHIELD_REPO_ROOT}/build/push_images.sh

pull-images:
		${ISHIELD_REPO_ROOT}/build/pull_images.sh

############################################################
# bundle section
############################################################

build-bundle:
		@if [ "$(ISHIELD_ENV)" = local ]; then \
			$(ISHIELD_REPO_ROOT)/build/build_bundle.sh; \
		else \
			$(ISHIELD_REPO_ROOT)/build/build_bundle_ocm.sh; \
		fi

############################################################
# clean section
############################################################
clean::

############################################################
# check copyright section
############################################################
copyright-check:
	 - $(ISHIELD_REPO_ROOT)/build/copyright-check.sh $(TRAVIS_BRANCH)

############################################################
# unit test section
############################################################

test-unit: test-init test-verify

test-init:
	cd $(SHIELD_DIR) &&  go test -v  $(shell cd $(SHIELD_DIR) && go list ./... | grep -v /vendor/ | grep -v /pkg/util/kubeutil | grep -v /pkg/util/sign/pgp) > $(TMP_DIR)results.txt

test-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)results.txt | grep "FAIL:"))
	cat $(TMP_DIR)results.txt
	@$(if $(strip $(FAILURES)), echo "One or more unit tests failed. Failures: $(FAILURES)"; exit 1, echo "All unit tests passed successfully."; exit 0)


############################################################
# e2e test section
############################################################

.PHONY: test-e2e test-e2e-kind test-e2e-remote test-e2e-common test-e2e-clean-common
.PHONY: check-kubeconfig create-kind-cluster setup-image pull-images push-images-to-local delete-kind-cluster
.PHONY: install-crds setup-ishield-env install-operator setup-tmp-cr setup-test-resources setup-test-env e2e-test delete-test-env delete-keyring-secret delete-operator clean-tmp delete-operator
.PHONY: create-ns create-key-ring tag-images-to-local


#.PHONY: kind-bootstrap-cluster-dev
#kind-bootstrap-cluster-dev: kind-create-cluster install-crds install-operator

.EXPORT_ALL_VARIABLES:
TEST_SIGNERS=TestSigner
TEST_SIGNER_SUBJECT_EMAIL=signer@enterprise.com
TEST_SAMPLE_SIGNER_SUBJECT_EMAIL=test@enterprise.com
TEST_SECRET=keyring_secret
TMP_CR_FILE=$(TMP_DIR)apis_v1alpha1_integrityshield.yaml
TMP_CR_UPDATED_FILE=$(TMP_DIR)apis_v1alpha1_integrityshield_update.yaml
# export KUBE_CONTEXT_USERNAME=kind-test-managed

test-e2e: export KUBECONFIG=$(SHIELD_OP_DIR)kubeconfig_managed
# perform test in a kind cluster after creating the cluster
test-e2e: create-kind-cluster setup-image test-e2e-common test-e2e-clean-common delete-kind-cluster

# perform test in an existing kind cluster and do not clean
test-e2e-kind: push-images-to-local test-e2e-common

# perform test in an existing cluster (e.g. ROKS, OCP etc.)
test-e2e-remote: test-e2e-common test-e2e-clean-common

# common steps to do e2e test in an existing cluster
test-e2e-common:  check-local-test check-kubeconfig install-crds setup-ishield-env install-operator setup-tmp-cr setup-test-resources setup-test-env e2e-test


# common steps to clean e2e test resources in an existing cluster
test-e2e-clean-common: delete-test-env delete-keyring-secret delete-operator clean-tmp

check-kubeconfig:
	@if [ -z "$(KUBECONFIG)" ]; then \
		echo KUBECONFIG is empty.; \
		exit 1;\
	fi

check-local-test:
	@if [ -z "$(TEST_LOCAL)" ]; then \
		echo TEST_LOCAL is empty. Please set true for local test.; \
		exit 1;\
	fi

create-kind-cluster:
	@echo "creating cluster"
	# kind create cluster --name test-managed
	bash $(SHIELD_OP_DIR)test/create-kind-cluster.sh
	kind get kubeconfig --name test-managed > $(SHIELD_OP_DIR)kubeconfig_managed

delete-kind-cluster:
	@echo deleting cluster
	kind delete cluster --name test-managed

setup-image: build-images push-images-to-local

tag-images-to-local:
	@echo tag image for local registry
	docker tag $(ISHIELD_SERVER_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION)
	docker tag $(ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION)
	docker tag $(ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION) $(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)

push-images-to-local: tag-images-to-local
	@echo push image into local registry
	docker push $(TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION)
	docker push $(TEST_ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION)
	docker push $(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)

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
	yq write -i $(TMP_CR_UPDATED_FILE) spec.signPolicy.signers[1].subjects[1].email $(TEST_SAMPLE_SIGNER_SUBJECT_EMAIL)

e2e-test:
	@echo
	@echo run test
	$(ISHIELD_REPO_ROOT)/build/check_test_results.sh


############################################################
# setup ishield
############################################################

install-ishield: check-kubeconfig install-crds setup-ishield-env install-operator create-cr 

uninstall-ishield: delete-webhook delete-cr delete-keyring-secret delete-operator

delete-webhook:
	@echo deleting webhook
	kubectl delete mutatingwebhookconfiguration ishield-webhook-config

setup-ishield-env: create-ns create-key-ring

create-ns:
	@echo
	@echo creating namespace
	kubectl create ns $(ISHIELD_OP_NS)

create-key-ring:
	@echo creating keyring-secret
	kubectl create -f $(SHIELD_OP_DIR)test/deploy/keyring_secret.yaml -n $(ISHIELD_OP_NS)

install-crds:
	@echo installing crds
	kustomize build $(SHIELD_OP_DIR)config/crd | kubectl apply -f -

delete-crds:
	@echo deleting crds
	kustomize build $(SHIELD_OP_DIR)config/crd | kubectl delete -f -

delete-keyring-secret:
	@echo
	@echo deleting keyring-secret
	kubectl delete -f $(SHIELD_OP_DIR)test/deploy/keyring_secret.yaml -n $(ISHIELD_OP_NS)

install-operator:
	@echo
	@echo setting image
	cp $(SHIELD_OP_DIR)config/manager/kustomization.yaml $(TMP_DIR)kustomization.yaml  #copy original file to tmp dir.
	cd $(SHIELD_OP_DIR)config/manager && kustomize edit set image controller=$(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)
	@echo installing operator
	kustomize build $(SHIELD_OP_DIR)config/default | kubectl apply --validate=false -f -
	cp $(TMP_DIR)kustomization.yaml $(SHIELD_OP_DIR)config/manager/kustomization.yaml  #put back the original file from tmp dir.

delete-operator:
	@echo
	@echo deleting operator
	kustomize build $(SHIELD_OP_DIR)config/default | kubectl delete -f -

create-cr:
	kubectl apply -f ${SHIELD_OP_DIR}config/samples/apis_v1alpha1_integrityshield.yaml -n $(ISHIELD_OP_NS)

delete-cr:
	kubectl delete -f ${SHIELD_OP_DIR}config/samples/apis_v1alpha1_integrityshield.yaml -n $(ISHIELD_OP_NS)

# create a temporary cr with update image names as well as signers
setup-tmp-cr:
	@echo
	@echo prepare cr
	@echo copy cr into tmp dir
	cp $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_local.yaml $(TMP_CR_FILE)
	@echo insert image
	yq write -i $(TMP_CR_FILE) spec.logger.image $(TEST_ISHIELD_LOGGING_IMAGE_NAME_AND_VERSION)
	yq write -i $(TMP_CR_FILE) spec.logger.imagePullPolicy Always
	yq write -i $(TMP_CR_FILE) spec.server.image $(TEST_ISHIELD_SERVER_IMAGE_NAME_AND_VERSION)
	yq write -i $(TMP_CR_FILE) spec.server.imagePullPolicy Always
	@echo setup signer policy
	yq write -i $(TMP_CR_FILE) spec.signPolicy.policies[2].namespaces[0] $(TEST_NS)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.policies[2].signers[0] $(TEST_SIGNERS)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.signers[1].name $(TEST_SIGNERS)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.signers[1].secret $(TEST_SECRET)
	yq write -i $(TMP_CR_FILE) spec.signPolicy.signers[1].subjects[0].email $(TEST_SIGNER_SUBJECT_EMAIL)
	@if [ "$(TEST_LOCAL)" ]; then \
		echo enable logAllResponse ; \
		yq write -i $(TMP_CR_FILE) spec.shieldConfig.log.logLevel trace ;\
		yq write -i $(TMP_CR_FILE) spec.shieldConfig.log.logAllResponse true ;\
		yq write -i $(TMP_CR_FILE) spec.shieldConfig.iShieldAdminUserGroup "system:masters,system:cluster-admins" ;\
	fi

create-tmp-cr:
	kubectl apply -f $(TMP_CR_FILE) -n $(ISHIELD_OP_NS)

delete-tmp-cr:
	kubectl delete -f $(TMP_CR_FILE) -n $(ISHIELD_OP_NS)


# list resourcesigningprofiles
list-rsp:
	kubectl get resourcesigningprofiles.apis.integrityshield.io --all-namespaces


# show rule table
show-rt:
	kubectl get cm ishield-rule-table-lock -n $(ISHIELD_NS) -o json | jq -r .binaryData.table | base64 -D | gzip -d

# show forwarder log
log-f:
	bash $(ISHIELD_REPO_ROOT)/scripts/watch_events.sh

log-s:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_server.sh

log-o:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_operator.sh

clean-tmp:
	@if [ -f "$(TMP_CR_FILE)" ]; then\
		rm $(TMP_CR_FILE);\
	fi
	@if [ -f "$(TMP_CR_UPDATED_FILE)" ]; then\
		rm $(TMP_CR_UPDATED_FILE);\
	fi

.PHONY: sec-scan

sec-scan:
	$(ISHIELD_REPO_ROOT)/build/sec_scan.sh

.PHONY: sonar-go-test-ishield sonar-go-test-op

sonar-go-test-ishield:
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		make go/gosec-install; \
	fi
	@echo "-> Starting sonar-go-test"
	@echo "--> Starting go test"
	cd $(SHIELD_DIR) && go test -coverprofile=$(SHIELD_BASE_DIR)/coverage.out -json ./... | tee $(SHIELD_BASE_DIR)/report.json | grep -v '"Action":"output"'
	@echo "--> Running gosec"
	gosec -fmt sonarqube -out gosec.json -no-fail ./...
	@echo "---> gosec gosec.json"
	@cat gosec.json
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		echo "--> Running sonar-scanner"; \
		sonar-scanner --debug; \
	fi

sonar-go-test-op:
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		make go/gosec-install; \
	fi
	@echo "-> Starting sonar-go-test"
	@echo "--> Starting go test"
	cd $(SHIELD_OP_DIR) && go test -coverprofile=$(SHIELD_OP_BASE_DIR)/coverage.out -json ./... | tee $(SHIELD_OP_BASE_DIR)/report.json | grep -v '"Action":"output"'
	@echo "--> Running gosec"
	gosec -fmt sonarqube -out gosec.json -no-fail ./...
	@echo "---> gosec gosec.json"
	@cat gosec.json
	@if [ "$(ISHIELD_ENV)" = remote ]; then \
		echo "--> Running sonar-scanner"; \
		sonar-scanner --debug; \
	fi

.PHONY: publish

publish:
	$(ISHIELD_REPO_ROOT)/build/publish_images.sh
	$(ISHIELD_REPO_ROOT)/build/publish_bundle_ocm.sh
