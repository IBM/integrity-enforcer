NAME=localhost:5000/integrity-shield-checker
VERSION=0.1.6

.PHONY: build deploy undeploy

build:
	@echo building binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/server ./
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)

deploy:
	kustomize build ./deploy | kubectl apply -n integrity-shield-operator-system -f -

undeploy:
	kustomize build ./deploy | kubectl delete -n integrity-shield-operator-system -f -


