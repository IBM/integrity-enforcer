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

REPO_ROOT=./..
SERVICE_NAME ?=iv-server
IMAGE_REMOTE ?=integrityverifier/iv-server:0.0.3
IMAGE_LOCAL ?=iv-server:local
KEYDIR ?= ./cert
BASEDIR ?= ./deployment
IV_NS ?= iverifier
DOCKERFILE ?= ./image/Dockerfile

LOGG_BASEDIR ?=$(REPO_ROOT)/logging/
LOGG_IMAGE_REMOTE ?=integrityverifier/iv-logging:0.0.3
LOGG_IMAGE_LOCAL ?=iv-logging:local

SS_BASEDIR ?=$(REPO_ROOT)/signservice/
SS_IMAGE_REMOTE ?=integrityverifier/iv-signservice:0.0.3
SS_IMAGE_LOCAL ?=signservice:dev

CA ?=$(shell openssl base64 -A <'$(KEYDIR)/ca.crt')

image/iv-server: $(shell find . -name '*.go')
		CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $@ ./cmd/$(SERVICE_NAME)

image/signservice: $(shell find $(SS_BASEDIR) -name '*.go')
		CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $(SS_BASEDIR)/build/_output/signservice $(SS_BASEDIR)/cmd/signservice

util-build: $(shell find . -name '*.go')
		CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $@ ./cmd/sig-util

build: image/iv-server
	docker build -f $(DOCKERFILE) -t $(IMAGE_LOCAL) image/

push: build
	docker tag $(IMAGE_LOCAL) $(IMAGE_REMOTE)
	docker push $(IMAGE_REMOTE)

certs: check-iv-env
	echo $(KEYDIR)
	./gencerts   "$(SERVICE_NAME)" "$(IV_NS)" "$(KEYDIR)"

deploy: check-iv-env
	# kubectl  create -f $(BASEDIR)/sampleregkey.yaml  -n $(IV_NS)
	kubectl create -f $(BASEDIR)/verifierPolicyCR.yaml -n $(IV_NS) --validate=false
	kubectl create -f $(BASEDIR)/verifierConfigCR.yaml -n $(IV_NS) --validate=false
	kubectl  create -f $(BASEDIR)/rbac.yaml -n $(IV_NS)
	kubectl -n $(IV_NS) create secret tls $(SERVICE_NAME)-tls \
		--cert "$(KEYDIR)/$(SERVICE_NAME)-tls.crt" \
		--key "$(KEYDIR)/$(SERVICE_NAME)-tls.key"
	cat $(BASEDIR)/role-binding.yaml | yq w - subjects[0].namespace $(IV_NS) | kubectl create -f - -n $(IV_NS)
	kubectl create -f $(BASEDIR)/$(DEPLOYMENT_YAML) -n $(IV_NS)
	kubectl create -f $(BASEDIR)/service.yaml -n $(IV_NS)
	cat $(BASEDIR)/webhook_config.yaml | yq w - webhooks[0].name $(SERVICE_NAME).$(IV_NS).svc | \
	     yq w - webhooks[0].clientConfig.service.namespace $(IV_NS) | \
	     yq w - webhooks[0].clientConfig.caBundle $(shell openssl base64 -A <'$(KEYDIR)/ca.crt') | \
		 kubectl create -f - -n $(IV_NS) --validate=false

delete: check-iv-env
	kubectl delete -f $(BASEDIR)/webhook_config.yaml -n $(IV_NS)
	kubectl delete -f $(BASEDIR)/service.yaml -n $(IV_NS)
	kubectl delete -f $(BASEDIR)/$(DEPLOYMENT_YAML) -n $(IV_NS)
	kubectl delete -f $(BASEDIR)/role-binding.yaml -n $(IV_NS)
	kubectl delete secret $(SERVICE_NAME)-tls -n $(IV_NS)
	kubectl delete -f $(BASEDIR)/rbac.yaml -n $(IV_NS)
	kubectl delete -f $(BASEDIR)/verifierPolicyCR.yaml -n $(IV_NS) --validate=false
	kubectl delete -f $(BASEDIR)/verifierConfigCR.yaml -n $(IV_NS) --validate=false
	# kubectl delete -f $(BASEDIR)/sampleregkey.yaml  -n $(IV_NS)

init:
	kubectl create -f $(BASEDIR)/verifierPolicyCRD.yaml --validate=false
	kubectl create -f $(BASEDIR)/verifierConfigCRD.yaml --validate=false
	kubectl create -f $(BASEDIR)/ResourceSignature.yaml --validate=false

init-delete:
	kubectl delete -f $(BASEDIR)/ResourceSignature.yaml
	kubectl delete -f $(BASEDIR)/verifierPolicyCRD.yaml
	kubectl delete -f $(BASEDIR)/verifierConfigCRD.yaml


get-all: check-iv-env
	kubectl get all -n $(IV_NS)

log-server: check-iv-env check-iv-server
	kubectl logs -n $(IV_NS) -f $(IV_SERVER_POD) -c server

log-logging: check-iv-env check-iv-server
	kubectl logs -n $(IV_NS) -f $(IV_SERVER_POD) -c logging

log-forwarder: log-logging

log-fw: log-forwarder

sleep:
	sleep 5

build-logging:
	docker build -t $(LOGG_IMAGE_LOCAL) $(LOGG_BASEDIR)

#build-sign: image/signservice
build-sign:
	docker build -t $(SS_IMAGE_LOCAL) $(SS_BASEDIR)

push-logging:
	docker tag $(LOGG_IMAGE_LOCAL) $(LOGG_IMAGE_REMOTE)
	docker push $(LOGG_IMAGE_REMOTE)

push-sign:
	docker tag $(SS_IMAGE_LOCAL) $(SS_IMAGE_REMOTE)
	docker push $(SS_IMAGE_REMOTE)

.PHONY : get-all deploy delete build push log-server

make log-json: log-server  | grep -v 'kubectl ' | jq . --unbuffered

refresh: delete push build-logging push-logging deploy sleep get-all

create: build push build-logging push-logging deploy sleep get-all


dev-config:
	kubectl create cm verifier-config --from-file cmd/$(SERVICE_NAME)/config.json -n $(IV_NS)

make copy-log: check-iv-env check-iv-server
	kubectl cp $(IV_NS)/$(IV_SERVER_POD):/iv-app/public/inout.log ./inout.log
	kubectl cp $(IV_NS)/$(IV_SERVER_POD):/iv-app/public/trace.log ./trace.log


check-iv-env:
ifndef IV_NS
	$(error IV_NS is undefined)
endif

ifndef IV_ENV
	$(error IV_ENV is undefined)
endif

ifeq ($(IV_ENV),roks)
$(eval DEPLOYMENT_YAML := remote_deployment_roks.yaml)
endif

ifeq ($(IV_ENV),remote)
$(eval DEPLOYMENT_YAML := remote_deployment.yaml)
endif

ifeq ($(IV_ENV),local)
DEPLOYMENT_YAML := deployment.yaml
endif

ifndef DEPLOYMENT_YAML
$(error IV_ENV must be set from "roks", "remote" or "local")
endif


check-iv-server:
	$(eval IV_SERVER_POD := $(shell kubectl get pod -n $(IV_NS) | grep Running | grep $(SERVICE_NAME)- | awk '{print $$1}'))
ifndef IV_SERVER_POD
	$(error IV_SERVER_POD is undefined)
endif



