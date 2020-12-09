## Signing Multiple ACM policies.

You will use Integrity Verifier to protect integrity of all `ACM policies` created in an ACM managed cluster(s). Once you enable Integrity Verifier protection in an ACM managed cluster(s) as described in [doc](README_DISABLE_IV_PROTECTION_ACM_ENV.md), you will need to sign any `ACM policies` before creating or updating it.

The following steps describe how to sign ACM polices as below.

1. Go to the source of your cloned `policy-collection` GitHub repository in the host.  
    ```
    $ cd policy-collection
    ```
    You will find ACM polices under `stable` and `community` directories.

2.  Create signature annotations to ACM policies files in the cloned `policy-collection` GitHub repository.

      Use the utility script [acm-sign-policy.sh](https://github.com/IBM/integrity-enforcer/blob/master/scripts/acm-sign-policy.sh) for signing ACM polices to be deployed to an ACM managed cluster.

      The following example shows how to use the utility script [acm-sign-policy.sh] to append signature annotations to ACM policies files found in `community` directory with the following parameters:
      - `signer@enterprise.com` - The default `signer` email, or change it to your own `signer` email.
      - `community` - the name of the directory of ACM polices to be signed

      ```
      $ cd policy-collection
      $ curl -s  https://raw.githubusercontent.com/open-cluster-management/integrity-verifier/master/scripts/ACM/acm-sign-policy.sh | bash -s \
                    signer@enterprise.com \
                    community
      ```

      The utility script [acm-sign-policy.sh] will append signature annotation to each original file, which is backed up before annotating (e.g. `policy-integrity.yaml`  will be backed up as `policy-integrity.yaml.backup`). 

      Create `.gitignore` in `policy-collection` directory and add `*.backup` to `.gitignore` to avoid commiting backup files to GitHub repository.
    
  3.  Commit the signed ACM policies files to the `policy-collection` GitHub repository.

      The following example shows how to commit the signed polices files to the forked`policy-collection` GitHub repository.

       ```
       $ cd policy-collection
       $ git status
       $ git add `.gitignore`
       $ git add -u
       $ git commit -m "Signature annotation added to ACM policies"
       $ git push origin master
       ```

       Once you commit the signed policy files to the `policy-collection` GitHub repository, the ACM hub cluster will successfully create or update ACM polices in an ACM managed cluster(s) since Integrity Verifier protection will successfully verify the ACM policies with signature annotations.

       Confirm the status (i.e. Compliance) of ACM polices in the ACM hub cluster.

       Any further changes to ACM policies requires the signing process described above.
