import boto3
import csv
from iam_policies import list_user_policies, list_group_policies, list_role_policies, get_policy_document
from kms_policies import list_kms_key_policies
from sso_policies import list_sso_permissions

def list_user_permissions():
    iam = boto3.client('iam')
    sso_admin = boto3.client('sso-admin')
    kms = boto3.client('kms')
    # Create CSV and Excel files which creates the follwing headers User/Key ID", "Type", "Policy Type/Principal Type", "Policy Name/Principal", "Policy Document
    with open('user_permissions.csv', mode='w', newline='') as csv_file, open('parsed_policies.csv', mode='w', newline='') as excel_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["User/Key ID", "Type", "Policy Type/Principal Type", "Policy Name/Principal", "Policy Document"])

        excel_fieldnames = [
            "UserName", "Entity", "PolicyType", "Version", "Action", "Effect", "Resource",
            "Condition_StringLike_iam:PassedToService", "Condition_StringLike_iam:AWSServiceName"
        ]
        excel_writer = csv.DictWriter(excel_file, fieldnames=excel_fieldnames)
        excel_writer.writeheader()

        paginator = iam.get_paginator('list_users')
        users = []
        for page in paginator.paginate():
            users.extend(page['Users'])
        # checks if there are any IAM users if not then it prints "No IAM users found" and exits
        if not users:
            print("No IAM users found")
        else:
            for user in users:
                user_name = user['UserName']
                groups = iam.list_groups_for_user(UserName=user_name)['Groups']
                if not groups:
                    csv_writer.writerow([user_name, "User", "", "No groups for user", ""])
                else:
                    for group in groups:
                        group_name = group['GroupName']
                        list_group_policies(iam, group_name, user_name, csv_writer, excel_writer)

                list_user_policies(iam, user_name, csv_writer, excel_writer)

                attached_roles = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                if not attached_roles:
                    csv_writer.writerow([user_name, "User", "", "No roles for user", ""])
                else:
                    for policy in attached_roles:
                        policy_arn = policy['PolicyArn']
                        policy_document = get_policy_document(iam, policy_arn)
                        if 'Statement' in policy_document:
                            for statement in policy_document['Statement']:
                                if 'Action' in statement and 'sts:AssumeRole' in statement['Action']:
                                    if 'Resource' in statement:
                                        role_arns = statement['Resource']
                                        if not isinstance(role_arns, list):
                                            role_arns = [role_arns]
                                        for role_arn in role_arns:
                                            role_name = role_arn.split('/')[-1]
                                            list_role_policies(iam, role_name, user_name, csv_writer, excel_writer)
        # writes thhe KMS key policies to the csv file 
        csv_writer.writerow(["KMS Key ID", "KMS Key ARN", "Policy Name/Principal Type", "Principal/Policy Name", "Policy Document"])
        kms_fieldnames = ["KeyId", "Type", "PolicyType", "Principal"]
        kms_excel_writer = csv.DictWriter(excel_file, fieldnames=kms_fieldnames)
        kms_excel_writer.writeheader()
        list_kms_key_policies(kms, csv_writer, kms_excel_writer)

        list_sso_permissions(sso_admin, 'sso_permissions.csv', excel_writer)


def main():
    list_user_permissions()

if __name__ == "__main__":
    main()
