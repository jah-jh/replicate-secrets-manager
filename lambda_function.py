from os import environ
import boto3


targetRegion = environ.get('TargetRegion')
if targetRegion == None:
    raise Exception('Environment variable "TargetRegion" must be set')

smSource = boto3.client('secretsmanager')
smTarget = boto3.client('secretsmanager', region_name=targetRegion)

kmsSource = boto3.client(service_name='kms')
kmsTarget = boto3.client(service_name='kms', region_name=targetRegion)


def lambda_handler(event, context):

    detail = event['detail']

    if detail['eventName'] == "CreateSecret":
        secretArn = detail['requestParameters']['name']
    elif detail['eventName'] == "PutSecretValue":
        secretArn = detail['requestParameters']['secretId']

    print('Retrieving new version of Secret "{0}"'.format(secretArn))

    newSecret = smSource.get_secret_value(SecretId=secretArn)
    secretName = newSecret['Name']
    currentVersion = newSecret['VersionId']
    secretString = newSecret['SecretString']

    replicaSecretExists = True
    print('Replicating secret "{0}" (Version {1}) to region "{2}"'.format(
        secretName, currentVersion, targetRegion))
    try:
        put_new_value(secretName, currentVersion, newSecret['SecretString'])
        pass
    except smTarget.exceptions.ResourceNotFoundException:
        print(
            'Secret "{0}" does not exist in target region "{1}". Attempting to create it now.'
            .format(secretName, targetRegion))
        replicaSecretExists = False
    except smTarget.exceptions.ResourceExistsException:
        print(
            'Secret version "{0}" has already been created, this must be a duplicate invocation'
            .format(currentVersion))
        pass

    if replicaSecretExists:
        update_secret_version(secretName, currentVersion)
    else:
        create_secret_target_region(secretArn, secretName, currentVersion,
                                    secretString)


    print('Secret {0} replicated successfully to region "{1}"'.format(
        secretName, targetRegion))


def find_or_create_custom_key(secret_name):

    source_key_id = smSource.describe_secret(SecretId=secret_name)['KmsKeyId']

    describe_source_key = kmsSource.describe_key(
        KeyId=source_key_id)['KeyMetadata']

    source_key_tags = kmsSource.list_resource_tags(KeyId=source_key_id)['Tags']
    source_key_description = describe_source_key['Description']
    source_key_usage = describe_source_key['KeyUsage']
    source_key_name = kmsSource.list_aliases(
        KeyId=source_key_id)['Aliases'][0]['AliasName'].split("/")[1]
    key_policy_source = kmsSource.get_key_policy(PolicyName="default",
                                                 KeyId=source_key_id)['Policy']

    try:
        kmsTarget.describe_key(KeyId="alias/" + source_key_name)
    except kmsTarget.exceptions.NotFoundException:
        print("Key Not Found, Creating key.....")
        response_create_key = kmsTarget.create_key(
            Policy=key_policy_source,
            Description=source_key_description,
            KeyUsage=source_key_usage,
            Origin="AWS_KMS",
            Tags=source_key_tags,
            BypassPolicyLockoutSafetyCheck=True)

        created_key_id = response_create_key['KeyMetadata']['KeyId']

        kmsTarget.create_alias(
            AliasName="alias/" + source_key_name, TargetKeyId=created_key_id)

        return response_create_key['KeyMetadata']['Arn']
    else:
        return kmsTarget.describe_key(KeyId="alias/" +
                                      source_key_name)['KeyMetadata']['Arn']


def put_new_value(secretName, currentVersion, NewSecretString):
    smTarget.put_secret_value(SecretId=secretName,
                              ClientRequestToken=currentVersion,
                              SecretString=NewSecretString)


def create_secret_target_region(secretArn, secretName, currentVersion,
                                secretString):
    secretMeta = smSource.describe_secret(SecretId=secretArn)
    if 'Description' in secretMeta.keys():
        Descr = secretMeta['Description']
    else:
        Descr = ""
    if 'KmsKeyId' in secretMeta.keys():
        replicaKmsKeyArn = find_or_create_custom_key(secretName)
        if replicaKmsKeyArn is None:
            raise Exception(
                "Error during getting or creating KMS key in {0} region".format(targetRegion)
            )

        smTarget.create_secret(Name=secretName,
                               ClientRequestToken=currentVersion,
                               KmsKeyId=replicaKmsKeyArn,
                               SecretString=secretString,
                               Description=Descr)
    else:
        smTarget.create_secret(Name=secretName,
                               ClientRequestToken=currentVersion,
                               SecretString=secretString,
                               Description=Descr)


def update_secret_version(secretName, currentVersion):
    secretMeta = smTarget.describe_secret(SecretId=secretName)
    for previousVersion, labelList in secretMeta['VersionIdsToStages'].items():
        if 'AWSCURRENT' in labelList and previousVersion != currentVersion:
            smTarget.update_secret_version_stage(
                SecretId=secretName,
                VersionStage='AWSCURRENT',
                MoveToVersionId=currentVersion,
                RemoveFromVersionId=previousVersion)

            break
