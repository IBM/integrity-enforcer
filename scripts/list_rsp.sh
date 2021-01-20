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
result=$(echo NAMESPACE NAME RULES TARGET_NAMESPACE)
for i in $( seq 0 $(($len - 1)) ); do
    rsp=$(echo -e "$rsplist" | jq .items[$i] | jq -c .)
    ns=$(echo -e "$rsp" | jq -r .metadata.namespace)
    t_ns=$(echo -e "$rsp" | jq .spec.targetNamespaceSelector | jq -c .)
    name=$(echo -e "$rsp" | jq -r .metadata.name)
    p_rule=$(echo -e "$rsp" | jq .spec.protectRules | jq -c .)
    i_rule=$(echo -e "$rsp" | jq .spec.ignoreRules | jq -c .)
    f_rule=$(echo -e "$rsp" | jq .spec.forceCheckRules | jq -c .)
    result=$(echo -e "${result}\n${ns} ${name} ${p_rule} ${t_ns}")
done

echo -e "$result" | column -t
