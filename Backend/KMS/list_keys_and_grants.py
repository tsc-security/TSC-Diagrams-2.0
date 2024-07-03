import boto3
from botocore.exceptions import ClientError
import json
from datetime import datetime
from collections import defaultdict

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(CustomJSONEncoder, self).default(obj)

def list_kms_key_policies():
    kms_client = boto3.client('kms')
    access_info = defaultdict(list)

    try:
        keys = kms_client.list_keys()
    except ClientError as e:
        print(f"Error listing keys: {e}")
        return access_info

    for key in keys['Keys']:
        key_id = key['KeyId']
        print(f"\nKey ID: {key_id}")
        
        try:
            key_policy = kms_client.get_key_policy(KeyId=key_id, PolicyName='default')
            policy_doc = json.loads(key_policy['Policy'])
            print("Key Policy:")
            print(json.dumps(policy_doc, indent=4))

            extract_principals_from_policy(key_id, policy_doc, access_info)
        except ClientError as e:
            print(f"Error getting key policy for {key_id}: {e}")

        # List grants
        try:
            grants = kms_client.list_grants(KeyId=key_id)
            print("Grants:")
            for grant in grants['Grants']:
                print(json.dumps(grant, indent=4, cls=CustomJSONEncoder))
                extract_principals_from_grant(key_id, grant, access_info)
        except ClientError as e:
            print(f"Error listing grants for {key_id}: {e}")

    return access_info

def extract_principals_from_policy(key_id, policy_doc, access_info):
    for statement in policy_doc.get('Statement', []):
        principals = statement.get('Principal', {})
        if isinstance(principals, dict):
            if 'AWS' in principals:
                aws_principals = principals['AWS']
                if isinstance(aws_principals, str):
                    access_info[key_id].append(aws_principals)
                elif isinstance(aws_principals, list):
                    access_info[key_id].extend(aws_principals)

def extract_principals_from_grant(key_id, grant, access_info):
    grantee_principal = grant.get('GranteePrincipal')
    if grantee_principal:
        access_info[key_id].append(grantee_principal)

def main():
    access_info = list_kms_key_policies()
    print("\nSummary of access to KMS keys:")
    for key_id, principals in access_info.items():
        print(f"\nKey ID: {key_id}")
        for principal in principals:
            print(f" - Principal: {principal}")

if __name__ == "__main__":
    main()