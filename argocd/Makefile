NAME=localhost:5000/argocd-builder
VERSION=latest

.PHONY: build deploy undeploy

build:
	@echo building binary for image
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-builder-core ./cmd/core
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)

build-cli:
	@echo building binary for cli
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o argocd-builder ./cmd/cli

build-core:
	@echo building binary for core
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o argocd-builder-core ./cmd/core

deploy:
	kustomize build ./deploy | kubectl apply -n sample-ns -f -

undeploy:
	kustomize build ./deploy | kubectl delete -n sample-ns -f -


