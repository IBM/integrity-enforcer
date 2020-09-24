#!/bin/bash

if ! [ -x "$(command -v curl)" ]; then
    echo 'Error: curl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v jq)" ]; then
    echo 'Error: curl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi


if [ "$#" -lt 3 ]; then
    echo 'Error: 3 arguments are required.' >&2
    echo ""
    echo 'Usage: ./create-signature.sh  <filepath>  <namespace>  <signer>  [<scope>]' >&2
    echo ""
    echo '<filepath>  : path to yaml file which will be signed (e.g. ./sample-configmap.yaml)' >&2
    echo '<namespace> : namespace in which the resource will be created (e.g. default)' >&2
    echo '<signer>    : signer email addrress to be used for signing (e.g. sample-signer@signer.com)' >&2
    echo '<scope>     : [optional] yaml paths to be signed (e.g. "metadata.name,spec.replicaCount")' >&2
    exit 1
fi

YAML_PATH=$1
RESOURCE_NS=$2
SIGNER_STRING=$3
SCOPE_STRING=$4

SIGN_NS=$IE_SIGN_NS
if [ -z "$SIGN_NS" ]; then
    SIGN_NS="ie-sign"
fi

SIGNSERVICE_URL=$IE_SIGNSERVICE_URL
if [ -z "$SIGNSERVICE_URL" ]; then
    SIGNSERVICE_URL="https://localhost:8180"
fi

status_code=`curl --write-out %{http_code} -sk --output /dev/null $SIGNSERVICE_URL`
if [[ "$status_code" -ne 200 ]] ; then
    echo "Error response from signservice URL: status $status_code."
    exit 1
fi

file_option="'yaml=@"$YAML_PATH"'"
url_option="'"$SIGNSERVICE_URL"/pgpsign?signer="$SIGNER_STRING"&namespace="$RESOURCE_NS"&scope="$SCOPE_STRING"'"

rsig_yaml=`sh -c "curl -sk -X POST -F ${file_option} ${url_option}"`

if echo -e "$rsig_yaml" | grep --quiet "kind: ResourceSignature"; then
    # echo -e "${rsig_yaml}"
    echo -e "${rsig_yaml}" | kubectl apply -n $SIGN_NS --validate=false -f -
else
    echo -e "${rsig_yaml}"
fi

