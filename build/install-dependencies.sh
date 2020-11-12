#!/bin/bash

set -e

echo "INSTALL DEPENDENCIES GOES HERE!"

OS_NAME=$(uname -s)

OPERATOR_SDK_VERSION=v1.1.0

if ! [ -x "$(command -v operator-sdk)" ]; then

	if [[ "$OS_NAME" == "Linux" ]]; then
		curl -L https://github.com/operator-framework/operator-sdk/releases/download/$OPERATOR_SDK_VERSION/operator-sdk-$OPERATOR_SDK_VERSION-x86_64-linux-gnu -o operator-sdk
	elif [[ "$OS_NAME" == "Darwin" ]]; then
		curl -L https://github.com/operator-framework/operator-sdk/releases/download/$OPERATOR_SDK_VERSION/operator-sdk-$OPERATOR_SDK_VERSION-x86_64-apple-darwin -o operator-sdk
	fi
	chmod +x operator-sdk
	sudo mv operator-sdk /usr/local/bin/operator-sdk
	operator-sdk version
fi

OPM_VERSION=v1.15.1

if ! [ -x "$(command -v opm)" ]; then
	if [[ "$OS_NAME" == "Linux" ]]; then
	    OPM_URL=https://github.com/operator-framework/operator-registry/releases/download/$OPM_VERSION/linux-amd64-opm
	elif [[ "$OS_NAME" == "Darwin" ]]; then
	    OPM_URL=https://github.com/operator-framework/operator-registry/releases/download/$OPM_VERSION/darwin-amd64-opm
	fi

	echo $GOPATH
	wget -nv $OPM_URL -O $GOPATH/bin/opm
	chmod +x $GOPATH/bin/opm
	$GOPATH/bin/opm version
fi

if ! [ -x "$(command -v kustomize)" ]; then
	if [[ "$OS_NAME" == "Linux" ]]; then
		curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
	elif [[ "$OS_NAME" == "Darwin" ]]; then
		curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
	fi
	chmod +x ./kustomize
	mv ./kustomize $GOPATH/bin/kustomize
fi

echo "Finished setting up dependencies."
