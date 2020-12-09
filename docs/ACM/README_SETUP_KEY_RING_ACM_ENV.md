# How to deploy a verification key to an ACM managed cluster.

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Verifier on an ACM managed cluster via [ACM policies](https://github.com/open-cluster-management/policy-collection).
- An [ACM]((https://www.redhat.com/en/technologies/management/advanced-cluster-management)) hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command

## Verification Key Setup in an ACM managed cluster(s)
A secret resource (default name `keyring-secret`) which contains a public key should be setup in an ACM managed cluster(s) for enabling signature verification by Integrity Verifier. 

Setting up a verification key on an ACM managed cluster requires the following steps:
 - Step 1 Create signing and verification key pairs
 - Step 2 Deploy verification key to an ACM hub cluster so that it can probagate to a managed cluster(s).


### Step 1 Create signing and verification key pairs

To see how to create a verification key,  refer to [doc](../README_VERIFICATION_KEY_SETUP.md)


### Step 2 Deploy verification key to an ACM hub cluster so that it can probagate to a managed cluster(s).

First connect to an ACM hub cluster and execute the [acm-verification-key-setup.sh](https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh) script to setup a verification key on an ACM managed cluster(s) connected to the ACM hub cluster as follows.
 

```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          integrity-verifier-operator-system  \
          keyring-secret  \
          /tmp/pubring.gpg \
          environment:dev  |  kubectl apply -f -
```

We pass the following parameters:
- `integrity-verifier-operator-system` - The namespace where verification key would be created in managed cluster. This should be the namespace the one set in Step 1 in [doc](README_DEPLOY_IV_ACM_ENV.md)
- `keyring-secret` - The name of secret resource which would include the verification
- `/tmp/pubring.gpg` - The file path of the verification key exported. see [doc](../README_VERIFICATION_KEY_SETUP.md)
- `environment:dev` - We will use placement rule flags which are the labels/tags that idetifies a managed cluster(s). We use the flags to setup ACM placement rule that selects the managed clusters in which the verification key needs to be setup. (e.g. environment:dev).  See [doc](https://github.com/open-cluster-management/policy-collection)


### Delete verification key from hub cluster and a managed cluster(s)

First connect to a ACM hub cluster where a verification key is already setup and execute the following script to delete the key from hub the cluster as well as a managed cluster(s).

```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          integrity-verifier-operator-system  \
          keyring-secret  \
          /tmp/pubring.gpg \
          environment:dev  |  kubectl delete -f -
```

We pass the following parameters:
- `integrity-verifier-operator-system` - The namespace where verification key would be created in managed cluster. This should be the namespace the one set in Step 1 in [doc](README_DEPLOY_IV_ACM_ENV.md)
- `keyring-secret` - The name of secret resource which would include the verification
- `/tmp/pubring.gpg` - The file path of the verification key exported. see [doc](../README_VERIFICATION_KEY_SETUP.md)
- `environment:dev` - We will use placement rule flags which are the labels/tags that idetifies a managed cluster(s). We use the flags to setup ACM placement rule that selects the managed clusters in which the verification key needs to be setup. (e.g. environment:dev).  See [doc](https://github.com/open-cluster-management/policy-collection)