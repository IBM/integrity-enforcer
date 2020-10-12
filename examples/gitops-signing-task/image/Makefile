DOCKERFILE ?= ./Dockerfile
IMAGE_REMOTE ?=gitops-sign-artifact:rc1
build:
	docker build -f $(DOCKERFILE) -t $(IMAGE_REMOTE) . --no-cache

push:
	docker push $(IMAGE_REMOTE)

.PHONY : build push

prepare: build push
