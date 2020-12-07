# How to deploy verification key to managed cluster


## Verification key Type
`pgp`: use [gpg key](https://www.gnupg.org/index.html) for signing.



### GPG Key Setup

First, you need to export public key to a file. The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).


### Deploy verification key to hub cluster so that it can probagate to managed cluster
First connect to a ACM hub cluster and execute the following commands to setup keys on managed clusters connectted to the hub cluster.

Usage: ocm-verification-key-setup.sh <NAMESPACE> <PUBRING-KEY-NAME> <PUBRING-KEY-VALUE> <PLACEMENT-RULE-KEY-VALUE-PAIR> <DELETE-FLAG>
       - <NAMESPACE>:  The namespace in the hub cluster and managed cluster where the verification key would be created
       - <PUBRING-KEY-NAME>:  The name of the verification key, which should be same as the key setup used for deploying Integrity Verifiier. see [Doc](README_QUICK.md). 
       - <PUBRING-KEY-VALUE>: The encoded value of the verifcaton key 
       - <PLACEMENT-RULE-KEY-VALUE-PAIR>: To select the managed clusters in which verification key needs to be setup,  use placement rule flags.
       - <DELETE-FLAG>:  If the flag set to `false`,  key would be setup in hub and managed cluster. If the flag set to `true`, key would be deleted from hub and managed cluster.
       

```
$ cd scripts
$ ./ocm-verification-key-setup.sh 
          integrity-verifier-operator-system  \  
          keyring-secret  \
          $(cat /tmp/pubring.gpg | base64 -w 0) \
          environment:dev \
		  false

```


### Delete verification key to hub cluster so that it can probagate to managed cluster
First connect to a ACM hub cluster where a verification key is alreadt setup and execute the following commands to delete keys from hubcluster as well as managed cluster.

```
$ cd scripts
$ ./ocm-verification-key-setup.sh 
          integrity-verifier-operator-system  \
          keyring-secret  \
          $(cat /tmp/pubring.gpg | base64 -w 0) \
          environment:dev \
		  true

```

Pass two parameters 
1.  Namespace

    `integrity-verifier-operator-system`  is the target namespace where verification key would be created in managed cluster. 
     (the namespace where integrity enforcer would be deployed in managed cluster)
        
2.  Verification key 

    Pass the encoded content of /tmp/pubring.gpg : `$(cat /tmp/pubring.gpg | base64 -w 0)`
        
