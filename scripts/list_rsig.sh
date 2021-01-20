#!/bin/bash

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v jq)" ]; then
    echo 'Error: jq is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v column)" ]; then
    echo 'Error: column is not installed.' >&2
    exit 1
fi

if [ -z "$ISHIELD_NS" ]; then
    echo "ISHIELD_NS is empty. Please set namespace name for integrity-shield."
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    date='date -u -d @'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    date='date -u -r '
fi

rsiglist=$(kubectl get rsig --all-namespaces -o json)
# echo -e "${rsigdata}"
len=$(echo -e "$rsiglist" | jq .items | jq length)
result=$(echo NAMESPACE NAME SIGNED_OBJECT SIGNED_TIME\(UTC\))
for i in $( seq 0 $(($len - 1)) ); do
    rsig=$(echo -e "$rsiglist" | jq .items[$i] | jq -c .)
    ns=$(echo -e "$rsig" | jq -r .metadata.namespace)
    name=$(echo -e "$rsig" | jq -r .metadata.name)
    msg=$(echo -e "$rsig" | jq -r '.spec.data[0].message' | base64 -D | gzip -d)
    # echo -e "$msg"
    kind=$(echo -e "$msg" | yq r - -j | jq -r .kind)
    obj_name=$(echo -e "$msg" | yq r - -j | jq -r .metadata.name)
    sigtime=$(echo -e "$rsig" | jq -r '.metadata.labels."integrityshield.io/sigtime"')
    sigtime_date=$(${date}${sigtime} +'%Y-%m-%dT%H:%M:%SZ')
    result=$(echo -e "${result}\n${ns} ${name} kind=${kind},name=${obj_name} ${sigtime_date}")
done

echo -e "$result" | column -t
