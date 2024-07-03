import boto3
import json
import csv
from utils import CustomJSONEncoder

def extract_principals_from_policy(key_id, policy_doc, csv_writer, excel_writer):
    for statement in policy_doc.get('Statement', []):
        principals = statement.get('Principal', {})
        if isinstance(principals, dict):
            if 'AWS' in principals:
                aws_principals = principals['AWS']
                if isinstance(aws_principals, str):
                    csv_writer.writerow([key_id, "KMS Key", "Policy Principal", aws_principals])
                    excel_writer.writerow({
                        "KeyId": key_id,
                        "Type": "KMS Key",
                        "PolicyType": "Policy Principal",
                        "Principal": aws_principals
                    })
                elif isinstance(aws_principals, list):
                    for principal in aws_principals:
                        csv_writer.writerow([key_id, "KMS Key", "Policy Principal", principal])
                        excel_writer.writerow({
                            "KeyId": key_id,
                            "Type": "KMS Key",
                            "PolicyType": "Policy Principal",
                            "Principal": principal
                        })
        elif isinstance(principals, str):
            csv_writer.writerow([key_id, "KMS Key", "Policy Principal", principals])
            excel_writer.writerow({
                "KeyId": key_id,
                "Type": "KMS Key",
                "PolicyType": "Policy Principal",
                "Principal": principals
            })

def extract_principals_from_grant(key_id, grant, csv_writer, excel_writer):
    grantee_principal = grant.get('GranteePrincipal')
    if grantee_principal:
        csv_writer.writerow([key_id, "KMS Key", "Grant Principal", grantee_principal])
        excel_writer.writerow({
            "KeyId": key_id,
            "Type": "KMS Key",
            "PolicyType": "Grant Principal",
            "Principal": grantee_principal
        })

def list_kms_key_policies(kms, csv_writer, excel_writer):
    keys = kms.list_keys()['Keys']
    for key in keys:
        key_id = key['KeyId']
        key_policy = kms.get_key_policy(KeyId=key_id, PolicyName='default')
        policy_doc = json.loads(key_policy['Policy'])
        extract_principals_from_policy(key_id, policy_doc, csv_writer, excel_writer)

        grants = kms.list_grants(KeyId=key_id)['Grants']
        for grant in grants:
            extract_principals_from_grant(key_id, grant, csv_writer, excel_writer)

def kms_parse():
    # Placeholder function to maintain structure
    pass
