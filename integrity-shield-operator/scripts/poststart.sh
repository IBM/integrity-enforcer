#!/bin/bash

TOKEN=`cat /var/run/secrets/kubernetes.io/serviceaccount/token`
K8S_API_URL=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT
ISHIELD_NS=$POD_NAMESPACE

# add finalizer to all Integrity Shield CRs in ISHIELD_NS
cr_name_list=`curl -sk -X GET -H "Authorization: Bearer $TOKEN" $K8S_API_URL/apis/apis.integrityshield.io/v1alpha1/namespaces/$ISHIELD_NS/integrityshields | jq -r .items[].metadata.name`
IFS=$'\n'
for cr_name in $cr_name_list
do
    curl -sk -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/merge-patch+json" $K8S_API_URL/apis/apis.integrityshield.io/v1alpha1/namespaces/$ISHIELD_NS/integrityshields/$cr_name -d '{"metadata":{"finalizers":["cleanup.finalizers.integrityshield.io"]}}'
done

