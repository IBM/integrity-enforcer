# How to deploy verification key to an [ACM](https://www.redhat.com/en/technologies/management/advanced-cluster-management) managed cluster.

## Prerequisites
​
The following prerequisites must be satisfied to deploy Integrity Verifier on a cluster.
- An ACM hub cluster with one or more managed cluster attached to it and cluster admin access to the cluster to use `oc` or `kubectl` command
- A secret resource (keyring-secret) which contains public key and certificates should be setup in an ACM managed cluster(s) for enabling signature verification by Integrity Verifier.


## Verification key Type
`pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing.


### GPG Key Setup

First, you need to export a public key to a file. The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --armor --export signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).


### Deploy verification key to hub cluster so that it can probagate to managed cluster
First connect to a ACM hub cluster and execute the following commands to setup keys on managed clusters connectted to the hub cluster.

Usage: acm-verification-key-setup.sh <NAMESPACE> <PUBRING-KEY-NAME> <PUBRING-KEY-VALUE> <PLACEMENT-RULE-KEY-VALUE-PAIR> <DELETE-FLAG>
       - <NAMESPACE>:  The namespace in the hub cluster and managed cluster where the verification key would be created
       - <PUBRING-KEY-NAME>:  The name of the verification key, which should be same as the key setup used for deploying Integrity Verifiier. see [Doc](../README_QUICK.md). 
       - <PUBRING-KEY-FILE-PATH>: The file path of verification key (e.g. /tmp/pubring.gpg)
       - <PLACEMENT-RULE-KEY-VALUE-PAIR>: To select the managed clusters in which verification key needs to be setup,  use placement rule flags.
       


```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          integrity-verifier-operator-system  \
          keyring-secret  \
          /tmp/pubring.gpg \
          environment:dev  |  kubectl apply -f -
```


### Delete verification key to hub cluster so that it can probagate to managed cluster
First connect to a ACM hub cluster where a verification key is alreadt setup and execute the following commands to delete keys from hubcluster as well as managed cluster.

```
curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-verification-key-setup.sh | bash -s \
          integrity-verifier-operator-system  \
          keyring-secret  \
          /tmp/pubring.gpg \
          environment:dev  |  kubectl delete -f -
```

Pass the following parameters 
1.  Namespace

    `integrity-verifier-operator-system`  is the target namespace where verification key would be created in managed cluster. 
     (the namespace where integrity enforcer would be deployed in managed cluster)

2.  Verification key name

     Name of the verification to be used for deploying Integrity Verifier
        
3.  Verification key file path

    Pass the file path of verification key (e.g. /tmp/pubring.gpg).        

4.  Placement rule flags

   To select the managed clusters in which verification key needs to be setup,  use placement rule flags.
