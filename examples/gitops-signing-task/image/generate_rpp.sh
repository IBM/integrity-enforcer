#!/bin/bash

INPUT_FILE=$1

infile=$(find . -name "$INPUT_FILE")

infilebasename=$(basename -- "$infile")
echo "infilebasename: $infilebasename"
infilename="${infilebasename%.*}"

base_rpp='{"apiVersion":"research.ibm.com/v1alpha1","kind":"ResourceProtectionProfile","metadata":{"name":""},"spec":{"rules": [{"match":""}]}}'

rppfile="rpp-$infilebasename"

echo Generated outfile: $rppfile

if [ -f $rppfile ]; then
   rm $rppfile
fi

echo -e $base_rpp | yq r - --prettyPrint >> $rppfile

# Get the namespace
namespace=""
indx=0
while read -r line;
do
   if [ $line = 'Namespace' ]; then
      namespace=$(yq r -d$indx $INPUT_FILE metadata.name)
      break
   fi
   indx=$[$indx+1]
done < <(yq r -d'*' $INPUT_FILE kind)

echo namespace: $namespace

# Prepare RPP

# 1. set rpp name
rppname=rpp-$infilename
yq w -i $rppfile metadata.name $rppname


array=

# 2. set rules
cnt=0

yq r -d'*' $INPUT_FILE -j | while read doc;
do
#   echo doc: $doc

   kind=$(echo $doc | yq r - -j | jq -r '.kind')
   if [ $kind = 'Namespace' ]; then
     continue
   fi

   kind=$(echo $doc | yq r - -j | jq -r '.kind')
   name=$(echo $doc | yq r - -j | jq -r '.metadata.name')

   yq w -i $rppfile spec.rules.[0].match.[$cnt].kind $kind
   yq w -i $rppfile spec.rules.[0].match.[$cnt].name $name

   cnt=$[$cnt+1]
done

