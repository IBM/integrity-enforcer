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

rsplist=$(kubectl get rsp --all-namespaces -o json)
# echo -e "${rspdata}"
len=$(echo -e "$rsplist" | jq .items | jq length)
if [[ $len != "0" ]]; then
    result=$(echo NAMESPACE NAME RULES TARGET_NAMESPACE)
    for i in $( seq 0 $(($len - 1)) ); do
        rsp=$(echo -e "$rsplist" | jq .items[$i] | jq -c .)
        ns=$(echo -e "$rsp" | jq -r .metadata.namespace)
        t_ns=$(echo -e "$rsp" | jq .spec.targetNamespaceSelector | jq -c .)
        if [[ $t_ns == "null" ]]; then
            t_ns=$ns
        fi
        name=$(echo -e "$rsp" | jq -r .metadata.name)
        rule=$(echo -e "$rsp" | jq -c '{"protectRules":.spec.protectRules,"ignoreRules":.spec.ignoreRules,"forceCheckRules":.spec.forceCheckRules} | with_entries( select( .value != null ) )' | jq -c .)
        result=$(echo -e "${result}\n${ns} ${name} ${rule} ${t_ns}")
    done
    echo -e "$result" | column -t
fi

