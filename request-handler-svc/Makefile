NAME=localhost:5000/k8s-manifest-sigstore-request-handler-svc
VERSION=0.1.6

CERT_DIR ?= cert/
SERVICE_NAME ?= integrity-shield-api
K8S_MANIFEST_SIGSTORE_NS ?= k8s-manifest-sigstore
TMP_CERT_CONFIG_PATH ?= /tmp/api-crt.conf

.PHONY: build deploy undeploy

build:
	@echo building binary
	go mod tidy
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/ishield-api ./
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)

deploy:
	kustomize build ./deploy | kubectl apply -n k8s-manifest-sigstore -f -

undeploy:
	kustomize build ./deploy | kubectl delete -n k8s-manifest-sigstore -f -

gencerts:
	@if [ ! -f "$(CERT_DIR)tls.crt" ]; then \
		echo generating webhook tls certs into $(CERT_DIR) ; \
		mkdir -p $(CERT_DIR) ; \
		cd $(CERT_DIR) ; \
		cat ../crt.conf | sed 's/SERVICE_NAME_PLACEHOLDER/$(SERVICE_NAME)/g' | sed 's/NAMESPACE_PLACEHOLDER/$(K8S_MANIFEST_SIGSTORE_NS)/g' > $(TMP_CERT_CONFIG_PATH) ; \
		openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=$(SERVICE_NAME)_ca" ; \
		openssl genrsa -out tls.key 2048 ; \
		openssl req -new -key tls.key -subj "/CN=$(SERVICE_NAME).$(K8S_MANIFEST_SIGSTORE_NS).svc" -out tls.csr ; \
		openssl x509 -extfile $(TMP_CERT_CONFIG_PATH) -extensions v3_req -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt ; \
		cp ca.crt ca_crt ; \
	else \
		echo use existing tls certs in $(CERT_DIR) ; \
	fi

