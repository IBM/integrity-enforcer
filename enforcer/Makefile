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
SERVICE_NAME ?=ie-server
IMAGE_REMOTE ?=integrityenforcer/ie-server:latest
IMAGE_LOCAL ?=ie-server:local
KEYDIR ?= ./cert
BASEDIR ?= ./deployment
IE_NS ?= ienforcer
DOCKERFILE ?= ./image/Dockerfile

LOGG_BASEDIR ?=$(REPO_ROOT)/logging/
LOGG_IMAGE_REMOTE ?=integrityenforcer/ie-logging:latest
LOGG_IMAGE_LOCAL ?=ie-logging:local

SS_BASEDIR ?=$(REPO_ROOT)/signservice/
SS_IMAGE_REMOTE ?=integrityenforcer/ie-signservice:latest
SS_IMAGE_LOCAL ?=signservice:dev

CA ?=$(shell openssl base64 -A <'$(KEYDIR)/ca.crt')

image/ie-server: $(shell find . -name '*.go')
		CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $@ ./cmd/$(SERVICE_NAME)

image/signservice: $(shell find $(SS_BASEDIR) -name '*.go')
		CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $(SS_BASEDIR)/build/_output/signservice $(SS_BASEDIR)/cmd/signservice

util-build: $(shell find . -name '*.go')
		CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o $@ ./cmd/sig-util

build: image/ie-server
	docker build -f $(DOCKERFILE) -t $(IMAGE_LOCAL) image/

push: build
	docker tag $(IMAGE_LOCAL) $(IMAGE_REMOTE)
	docker push $(IMAGE_REMOTE)

certs: check-ie-env
	echo $(KEYDIR)
	./gencerts   "$(SERVICE_NAME)" "$(IE_NS)" "$(KEYDIR)"

deploy: check-ie-env
	# kubectl  create -f $(BASEDIR)/sampleregkey.yaml  -n $(IE_NS)
	kubectl create -f $(BASEDIR)/enforcePolicyCR.yaml -n $(IE_NS) --validate=false
	kubectl create -f $(BASEDIR)/enforcerConfigCR.yaml -n $(IE_NS) --validate=false
	kubectl  create -f $(BASEDIR)/rbac.yaml -n $(IE_NS)
	kubectl -n $(IE_NS) create secret tls $(SERVICE_NAME)-tls \
		--cert "$(KEYDIR)/$(SERVICE_NAME)-tls.crt" \
		--key "$(KEYDIR)/$(SERVICE_NAME)-tls.key"
	cat $(BASEDIR)/role-binding.yaml | yq w - subjects[0].namespace $(IE_NS) | kubectl create -f - -n $(IE_NS)
	kubectl create -f $(BASEDIR)/$(DEPLOYMENT_YAML) -n $(IE_NS)
	kubectl create -f $(BASEDIR)/service.yaml -n $(IE_NS)
	cat $(BASEDIR)/webhook_config.yaml | yq w - webhooks[0].name $(SERVICE_NAME).$(IE_NS).svc | \
	     yq w - webhooks[0].clientConfig.service.namespace $(IE_NS) | \
	     yq w - webhooks[0].clientConfig.caBundle $(shell openssl base64 -A <'$(KEYDIR)/ca.crt') | \
		 kubectl create -f - -n $(IE_NS) --validate=false

delete: check-ie-env
	kubectl delete -f $(BASEDIR)/webhook_config.yaml -n $(IE_NS)
	kubectl delete -f $(BASEDIR)/service.yaml -n $(IE_NS)
	kubectl delete -f $(BASEDIR)/$(DEPLOYMENT_YAML) -n $(IE_NS)
	kubectl delete -f $(BASEDIR)/role-binding.yaml -n $(IE_NS)
	kubectl delete secret $(SERVICE_NAME)-tls -n $(IE_NS)
	kubectl delete -f $(BASEDIR)/rbac.yaml -n $(IE_NS)
	kubectl delete -f $(BASEDIR)/enforcePolicyCR.yaml -n $(IE_NS) --validate=false
	kubectl delete -f $(BASEDIR)/enforcerConfigCR.yaml -n $(IE_NS) --validate=false
	# kubectl delete -f $(BASEDIR)/sampleregkey.yaml  -n $(IE_NS)

init:
	kubectl create -f $(BASEDIR)/enforcePolicyCRD.yaml --validate=false
	kubectl create -f $(BASEDIR)/enforcerConfigCRD.yaml --validate=false
	kubectl create -f $(BASEDIR)/ResourceSignature.yaml --validate=false

init-delete:
	kubectl delete -f $(BASEDIR)/ResourceSignature.yaml
	kubectl delete -f $(BASEDIR)/enforcePolicyCRD.yaml
	kubectl delete -f $(BASEDIR)/enforcerConfigCRD.yaml


get-all: check-ie-env
	kubectl get all -n $(IE_NS)

log-server: check-ie-env check-ie-server
	kubectl logs -n $(IE_NS) -f $(IE_SERVER_POD) -c server

log-logging: check-ie-env check-ie-server
	kubectl logs -n $(IE_NS) -f $(IE_SERVER_POD) -c logging

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
	kubectl create cm enforce-config --from-file cmd/$(SERVICE_NAME)/config.json -n $(IE_NS)

make copy-log: check-ie-env check-ie-server
	kubectl cp $(IE_NS)/$(IE_SERVER_POD):/ie-app/public/inout.log ./inout.log
	kubectl cp $(IE_NS)/$(IE_SERVER_POD):/ie-app/public/trace.log ./trace.log


check-ie-env:
ifndef IE_NS
	$(error IE_NS is undefined)
endif

ifndef IE_ENV
	$(error IE_ENV is undefined)
endif

ifeq ($(IE_ENV),roks)
$(eval DEPLOYMENT_YAML := remote_deployment_roks.yaml)
endif

ifeq ($(IE_ENV),remote)
$(eval DEPLOYMENT_YAML := remote_deployment.yaml)
endif

ifeq ($(IE_ENV),local)
DEPLOYMENT_YAML := deployment.yaml
endif

ifndef DEPLOYMENT_YAML
$(error IE_ENV must be set from "roks", "remote" or "local")
endif


check-ie-server:
	$(eval IE_SERVER_POD := $(shell kubectl get pod -n $(IE_NS) | grep Running | grep $(SERVICE_NAME)- | awk '{print $$1}'))
ifndef IE_SERVER_POD
	$(error IE_SERVER_POD is undefined)
endif



