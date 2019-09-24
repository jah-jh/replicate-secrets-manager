# secrets-manager-replication-tf-module
Work on TF module for AWS Secrets Manager(SM) replication.


## How it works
1. Secret is updated or created in original AWS Region.
2. CloudTrail receives a log with “eventName”: “PutSecretValue” or "eventName" : "CreateSecret".
3. CloudTrail passes this log to CloudWatch Events.
4. A filter in CloudWatch Events for this EventName triggers a Lambda function.
5. The Lambda function retrieves the secret value from the origin AWS Region.
6. The Lambda function then performs PutSecretValue or CreateSecret on a secret with the same name in the replica AWS Region.

If secret encrypted with custom KMS key, key will be created in replica region with same name, description, tags and policy  as in original region. Than secret will be created or updated with this KMS key.




### Usage:

Since module replicates secret on Event from SM, for initial replication you can run util/copy_all_secret.py.
Look at README in util/ 

To start module run:

```
make S_REG='source_region=<your_source_region>' T_REG='target_region=<your_target_region>' plan/apply
```

### Troubleshooting:

Lambda function writes log in CloudTrail. So logs can be found in  AWS Console Lambda->Functions->ReplicateSecretsToTargetRegion->Monitoring.
