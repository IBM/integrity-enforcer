#!/bin/bash

if ! [ -x "$(command -v docker)" ]; then
    echo 'Error: docker is not installed.' >&2
    exit 1
fi
if [ -z "$IE_REPO_ROOT" ]; then
   echo "IE_REPO_ROOT is empty. Please set root directory for IE repository"
   exit 1
fi


SS_BASEDIR=${IE_REPO_ROOT}/develop/signservice/signservice/
SS_IMAGE_REMOTE=integrityenforcer/ie-signservice:latest
SS_IMAGE_LOCAL=signservice:dev

SS_OPERATOR_BASEDIR=${IE_REPO_ROOT}/develop/signservice/signservice-operator/
SS_OPERATOR_IMAGE_NAME=signservice-operator
SS_OPERATOR_IMAGE_REPO=integrityenforcer
SS_OPERATOR_IMAGE_TAG_LOCAL=dev
SS_OPERATOR_IMAGE_TAG=dev
SS_OPERATOR_IMAGE_LOCAL=${SS_OPERATOR_IMAGE_NAME}:${SS_OPERATOR_IMAGE_TAG_LOCAL}
SS_OPERATOR_IMAGE_REMOTE=${SS_OPERATOR_IMAGE_REPO}/${SS_OPERATOR_IMAGE_NAME}:${SS_OPERATOR_IMAGE_TAG}


# Push signservice image
echo -----------------------------
echo [1/2] Pushing signservice image.
docker tag ${SS_IMAGE_LOCAL} ${SS_IMAGE_REMOTE}
docker push ${SS_IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""


# Push signservice-operator image
echo -----------------------------
echo [2/2] Pushing signservice-operator image.
docker tag ${SS_OPERATOR_IMAGE_LOCAL} ${SS_OPERATOR_IMAGE_REMOTE}
docker push ${SS_OPERATOR_IMAGE_REMOTE}
echo done.
echo -----------------------------
echo ""

echo Completed.
