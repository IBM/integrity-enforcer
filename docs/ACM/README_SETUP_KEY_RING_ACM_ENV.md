# How to deploy a verification key to an ACM managed cluster.

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Verifier on an ACM managed cluster via [ACM policies](https://github.com/open-cluster-management/policy-collection).
- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command

## Verification Key Setup
A secret resource (keyring-secret) which contains a public key should be setup in an ACM managed cluster(s) for enabling signature verification by Integrity Verifier. We describe how we could setup a verification key on an ACM managed cluster.
To see how to create a verification key,  refer to [doc](../README_VERIFICATION_KEY_SETUP.md)


### The script for setting up verification key to an ACM hub cluster so that it can probagate to a managed cluster(s)

We will use the script: [acm-verification-key-setup.sh](https://github.com/IBM/integrity-enforcer/blob/master/scripts/acm-verification-key-setup.sh) for setting up a verification key.

```
$ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
               NAMESPACE \
               PUBRING-KEY-NAME  \
               PUBRING_KEY_FILE_PATH \
               PLACEMENT-RULE-KEY-VALUE-PAIR
```

Pass the following parameters.

- NAMESPACE:  The namespace where verification key would be created in managed cluster. The should be the namespace where Integrity Verifier would be deployed in a managed cluster. (We will use integrity-verifier-operator-system namespace in this document.)
- PUBRING-KEY-NAME:  The name of the verification key to be used for deploying Integrity Verifier. (e.g. keyring-secret)
- PUBRING_KEY_FILE_PATH: The file path of the verification key (e.g. /tmp/pubring.gpg).
- PLACEMENT-RULE-KEY-VALUE-PAIR:  We will use placement rule flags which are the labels/tags that idetifies a managed cluster(s). We use the flags to setup ACM placement rule that selects the managed clusters in which the verification key needs to be setup. (e.g. environment:dev).  See [doc](https://github.com/open-cluster-management/policy-collection)

### Deploy verification key to an ACM hub cluster so that it can probagate to a managed cluster(s).

First connect to an ACM hub cluster and execute the following script to setup a veification key on a managed cluster(s) connected to the hub cluster.

Execute the script `acm-verification-key-setup.sh` as follows.

```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          integrity-verifier-operator-system  \
          keyring-secret  \
          /tmp/pubring.gpg \
          environment:dev  |  kubectl apply -f -
```


### Delete verification key to hub cluster so that it can probagate to managed cluster

First connect to a ACM hub cluster where a verification key is already setup and execute the following script to delete the key from hub the cluster as well as a managed cluster(s).

```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          integrity-verifier-operator-system  \
          keyring-secret  \
          /tmp/pubring.gpg \
          environment:dev  |  kubectl delete -f -
```
