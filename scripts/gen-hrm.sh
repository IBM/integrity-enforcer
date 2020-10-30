#! /bin/bash

if [ "$#" -lt 3 ]; then
    echo 'Error: 3 arguments are required.' >&2
    echo ""
    echo 'Usage: ./gen-hrm.sh  <name>  <namespace>  <chartfilepath>  [<configfilepath>]' >&2
    echo ""
    echo '<name>            : name for helm install (e.g. sample-chart-install)' >&2
    echo '<namespace>       : namespace for helm install (e.g. default)' >&2
    echo '<chartfilepath>   : filepath of tgz file (e.g. ./sample-chart.tgz)' >&2
    echo '<configfilepath>  : [optional] filepath of values file  (e.g. "./values.yaml")' >&2
    exit 1
fi

name=$1
namespace=$2
chart_file=$3
config_file=$4


chart=`cat $chart_file | base64`
prov=`cat ${chart_file}.prov | base64`
config=""
manifest=""
install_option=""
if [[ -z $config_file ]]; then
    config=""
    manifest=`helm template --no-hooks $name -n $namespace $chart_file | base64`
    install_option="${name} -n ${namespace} ${chart_file}"
else
    config=`cat $config_file | base64`
    manifest=`helm template --no-hooks $name -n $namespace $chart_file --values $config_file | base64`
    install_option="${name} -n ${namespace} ${chart_file} --values ${config_file}"
fi

content=`cat <<EOF  
apiVersion: apis.integrityenforcer.io/v1alpha1
kind: HelmReleaseMetadata
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  name: ${name}
  chart: ${chart}
  prov: ${prov}
  config: ${config}
  manifest: ${manifest}
  installOption: ${install_option}
EOF
`

echo -e "${content}"
