## Usage:


**copy_all_secrets.py** - is used to replicate all your secrets between regions. General purpose is make initial replication.

Script creates secret if it isnt existed in target region. 
Secret would be encrypted by KMS key with same name as in source region.


Next command copy all secrets from source to target regions. Only last version of secret will be copied.
```
./copy_all_secrets.py --source <your_source_region> --target <your_target_region>
```

If you want copy all versions, run
```
./copy_all_secrets.py --all-versions --source <your_source_region> --target <your_target_region>
```
