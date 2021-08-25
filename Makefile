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

SHELL=/bin/bash

# LOAD ENVIRNOMENT SETTINGS (must be done at first)
###########################
ifeq ($(ISHIELD_REPO_ROOT),)
$(error ISHIELD_REPO_ROOT is not set)
endif

ifeq ($(ISHIELD_NS),)
$(error ISHIELD_NS is not set)
endif

ifeq ($(ISHIELD_ENV),)
$(error ISHIELD_ENV is not set. Please set local or remote.)
endif

include  .env
export $(shell sed 's/=.*//' .env)

ifeq ($(ENV_CONFIG),)
$(error ENV_CONFIG is not set)
endif

include  $(ENV_CONFIG)
export $(shell sed 's/=.*//' $(ENV_CONFIG))


ifeq ($(ISHIELD_ENV), remote)
OPERATOR_IMG=$(ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)
CR=apis_v1alpha1_integrityshield.yaml
else
OPERATOR_IMG=$(TEST_ISHIELD_OPERATOR_IMAGE_NAME_AND_VERSION)
CR=apis_v1alpha1_integrityshield_local.yaml
endif

# COPYRIGHT
copyright:
	bash $(ISHIELD_REPO_ROOT)/scripts/copyright.sh

# LOG
log-server:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_server.sh
log-operator:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_operator.sh
log-observer:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_observer.sh
log-ac-server:
	bash $(ISHIELD_REPO_ROOT)/scripts/log_ac.sh

# BUILD
build-images:
	bash $(ISHIELD_REPO_ROOT)/scripts/build_images.sh

push-remote:
	bash $(ISHIELD_REPO_ROOT)/scripts/push_images_remote.sh


# DEPLOY
deploy-op:
	cd $(SHIELD_OP_DIR) && make deploy IMG=$(OPERATOR_IMG)

deploy-cr-gk:
	kubectl create -f $(SHIELD_OP_DIR)config/samples/$(CR) -n $(ISHIELD_NS)

deploy-cr-ac:
	kubectl create -f $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_ac.yaml -n $(ISHIELD_NS)

# UNDEPLOY
delete-op:
	cd $(SHIELD_OP_DIR) && make undeploy

delete-cr-gk:
	kubectl delete -f $(SHIELD_OP_DIR)config/samples/$(CR) -n $(ISHIELD_NS)

delete-cr-ac:
	kubectl delete -f $(SHIELD_OP_DIR)config/samples/apis_v1alpha1_integrityshield_ac.yaml -n $(ISHIELD_NS)

# TEST
e2e-test:
	@echo
	@echo run test
	$(ISHIELD_REPO_ROOT)/scripts/check_test_results.sh

test-e2e: export KUBECONFIG=$(SHIELD_OP_DIR)kubeconfig_managed
# perform test in a kind cluster after creating the cluster
test-e2e: create-kind-cluster build-images test-e2e-common test-e2e-clean-common delete-kind-cluster

# common steps to do e2e test in an existing cluster
test-e2e-common: check-kubeconfig deploy-op setup-test-env e2e-test

setup-test-env:
	@echo
	@echo creating test namespace
	kubectl create ns $(TEST_NS)
	kubectl create ns $(TEST_UNPROTECTED_NS)
	@echo deploying gatekeeper
	kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.5/deploy/gatekeeper.yaml

clean-test-env:
	@echo
	@echo deleting test namespace
	kubectl delete ns $(TEST_NS)
	kubectl delete ns $(TEST_UNPROTECTED_NS)
	@echo deleting gatekeeper
	kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.5/deploy/gatekeeper.yaml

create-kind-cluster:
	@echo "creating cluster"
	# kind create cluster --name test-managed
	bash $(SHIELD_OP_DIR)test/create-kind-cluster.sh
	kind get kubeconfig --name test-managed > $(SHIELD_OP_DIR)kubeconfig_managed

delete-kind-cluster:
	@echo deleting cluster
	kind delete cluster --name test-managed

check-kubeconfig:
	@if [ -z "$(KUBECONFIG)" ]; then \
		echo KUBECONFIG is empty.; \
		exit 1;\
	fi

# BUNDLE
build-bundle:
		$(ISHIELD_REPO_ROOT)/scripts/build_bundle.sh
