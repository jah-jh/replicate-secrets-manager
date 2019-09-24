#!/usr/bin/env python3

import sys
import getopt
import boto3


def main():

    session = boto3.session.Session(profile_name='strln')

    amazon_region_list_sm = session.get_available_regions('secretsmanager')
    amazon_region_list_kms = session.get_available_regions('kms')
    available_regions = set(amazon_region_list_sm) & set(
        amazon_region_list_kms)

    args = sys.argv[1:]

    if "--source" not in args or "--target" not in args:
        print("Set source and destination region\n\
Usage: {0} --source <source_region> --target <target_region>".format(
            sys.argv[0]))
        exit(1)

    options, reminder = getopt.getopt(
        args, ['--source', '--target', '--all-versions'],
        ['source=', 'target=', 'all-versions'])
    for opt, arg in options:
        if opt in '--source':
            sourceRegion = arg
        elif opt in '--target':
            targetRegion = arg

    if sourceRegion not in available_regions:
        print("The specified source region is not available for replication.\n\
Available regions:" + str(available_regions))
        exit(1)
    if targetRegion not in available_regions:
        print("The specified target region is not available for replication.\n\
Available regions:" + str(available_regions))
        exit(1)

    smSource = session.client(service_name='secretsmanager',
                              region_name=sourceRegion)

    smTarget = session.client(service_name='secretsmanager',
                              region_name=targetRegion)

    kmsSource = session.client(service_name='kms', region_name=sourceRegion)

    kmsTarget = session.client(service_name='kms', region_name=targetRegion)

    secret_lst = smSource.list_secrets(MaxResults=99)['SecretList']

    if '--all-versions' in args:
        for sec in secret_lst:
            copy_all_versions(sec, smSource, smTarget, kmsSource, kmsTarget)
    else:

        for sec in secret_lst:

            sec = smSource.get_secret_value(SecretId=sec['ARN'])
            secretName = sec['Name']
            currentVersion = sec['VersionId']

            #Check if secret already exists in target region
            replicaSecretExists = True
            print('Replicating secret "{0}" (Version {1}) to region "{2}"'.
                  format(secretName, currentVersion, targetRegion))
            try:
                smTarget.put_secret_value(SecretId=secretName,
                                          ClientRequestToken=currentVersion,
                                          SecretString=sec['SecretString'])

            except smTarget.exceptions.ResourceNotFoundException:
                print("Variable doesnt exist")
                replicaSecretExists = False
            except smTarget.exceptions.ResourceExistsException:
                print('Variables exists')

            if replicaSecretExists == False:
                secretMetaData = smSource.describe_secret(SecretId=secretName)
                if 'Description' not in secretMetaData.keys():
                    Desc = ""
                else:
                    Desc = secretMetaData['Description']
                if 'KmsKeyId' in secretMetaData.keys():
                    replicaKmsKeyArn = find_or_create_custom_key(
                        secretName, smSource, smTarget, kmsSource, kmsTarget, targetRegion)
                    if replicaKmsKeyArn is None:
                        raise Exception(
                            "Error during getting or creating KMS key from {0} region"
                            .format(targetRegion))
                        exit(1)
                    smTarget.create_secret(Name=secretName,
                                           SecretString=sec['SecretString'],
                                           KmsKeyId=replicaKmsKeyArn,
                                           ClientRequestToken=currentVersion,
                                           Description=Desc)
                else:
                    smTarget.create_secret(Name=secretName,
                                           ClientRequestToken=currentVersion,
                                           SecretString=sec['SecretString'],
                                           Description=Desc)

            else:
                secretMetaTarget = smTarget.describe_secret(
                    SecretId=secretName)
                for previousVersion, labelList in secretMetaTarget[
                        'VersionIdsToStages'].items():
                    if 'AWSCURRENT' in labelList and previousVersion != currentVersion:
                        print(
                            'Moving "AWSCURRENT" label from version "{0}" to new version "{1}"'
                            .format(previousVersion, currentVersion))
                        smTarget.update_secret_version_stage(
                            SecretId=secretName,
                            VersionStage='AWSCURRENT',
                            MoveToVersionId=currentVersion,
                            RemoveFromVersionId=previousVersion)
                        break


def find_or_create_custom_key(secret_name, smSource, smTarget, kmsSource,
                              kmsTarget, targetRegion):

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
        print("KMS Key for secret not found in {0} region, Creating key.....".format(targetRegion))
        response_create_key = kmsTarget.create_key(
            Policy=key_policy_source,
            Description=source_key_description,
            KeyUsage=source_key_usage,
            Origin="AWS_KMS",
            Tags=source_key_tags,
            BypassPolicyLockoutSafetyCheck=True)

        created_key_id = response_create_key['KeyMetadata']['KeyId']

        kmsTarget.create_alias(AliasName="alias/" + source_key_name,
                               TargetKeyId=created_key_id)

        return response_create_key['KeyMetadata']['Arn']
    else:
        return kmsTarget.describe_key(KeyId="alias/" +
                                      source_key_name)['KeyMetadata']['Arn']


def copy_all_versions(sec, smSource, smTarget, kmsSource, kmsTarget):
    secret_name = sec['Name']
    secretMetaData = smSource.describe_secret(SecretId=secret_name)
    if 'Description' not in secretMetaData.keys():
        Desc = ""
    else:
        Desc = secretMetaData['Description']

    version_list = smSource.list_secret_version_ids(SecretId=secret_name,
                                                    IncludeDeprecated=True,
                                                    MaxResults=99)

    target_versions_list = []

    try:
        smTarget.describe_secret(SecretId=secret_name)
    except smTarget.exceptions.ResourceNotFoundException:
        secret_exists_in_target_region = False
    else:
        print(
            "Seret {0} exists in target region. Version checking and synchronization...."
            .format(secret_name))
        target_versions = smTarget.list_secret_version_ids(
            SecretId=secret_name, MaxResults=99,
            IncludeDeprecated=True)['Versions']
        for t_vers in target_versions:
            target_versions_list.append(t_vers['VersionId'])
        secret_exists_in_target_region = True

    for version in version_list['Versions']:
        secret_data = smSource.get_secret_value(SecretId=secret_name,
                                                VersionId=version['VersionId'])
        version_id = version['VersionId']
        secret_string = secret_data['SecretString']

        if secret_exists_in_target_region is False:
            print("Secret {0} is new in target region. Trying to create....".
                  format(secret_name))
            if 'KmsKeyId' in secretMetaData.keys():
                replicaKmsKeyArn = find_or_create_custom_key(
                    secret_name, smSource, smTarget, kmsSource, kmsTarget)
            if replicaKmsKeyArn is None:
                raise Exception(
                        "Error during getting or creating KMS key from {0} region"
                        .format(targetRegion))
                exit(1)
            smTarget.create_secret(Name=secret_name,
                                   ClientRequestToken=version_id,
                                   KmsKeyId=replicaKmsKeyArn,
                                   SecretString=secret_string,
                                   Description=Desc)
            secret_exists_in_target_region = True
            print("Secret {0} created in target region".format(secret_name))
        else:
            if version_id not in target_versions_list:
                print("New version {0} is found. Trying to add...".format(
                    version_id))
                smTarget.put_secret_value(SecretId=secret_name,
                                          ClientRequestToken=version_id,
                                          SecretString=secret_string)
                print("Version {0} is added".format(version_id))
            else:
                print("Version {0} exists in target region".format(version_id))
                continue
    print("\n\n")


if __name__ == '__main__':
    main()
