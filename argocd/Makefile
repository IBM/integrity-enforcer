NAME=localhost:5000/argo-simulator
VERSION=latest

.PHONY: build deploy undeploy

build:
	@echo building binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/simulate-argocd ./
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)

deploy:
	kustomize build ./deploy | kubectl apply -n sample-ns -f -

undeploy:
	kustomize build ./deploy | kubectl delete -n sample-ns -f -


