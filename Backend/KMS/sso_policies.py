import boto3
import csv
import json

def get_permission_set_policies(sso_admin, instance_arn, permission_set_arn):
    inline_policy = sso_admin.get_inline_policy_for_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=permission_set_arn
    ).get('InlinePolicy', '{}')

    return json.loads(inline_policy)

def list_sso_permissions(sso_admin, csv_file_path, excel_writer):
    instances = sso_admin.list_instances()['Instances']
    with open(csv_file_path, mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Instance ARN", "Type", "Policy Type", "Permission Set Name", "Policy Document"])

        for instance in instances:
            instance_arn = instance['InstanceArn']
            permission_sets = sso_admin.list_permission_sets(InstanceArn=instance_arn)['PermissionSets']
            for permission_set_arn in permission_sets:
                permission_set_policies = get_permission_set_policies(sso_admin, instance_arn, permission_set_arn)
                permission_set_name = sso_admin.describe_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ).get('PermissionSet', {}).get('Name', 'Unknown Permission Set')

                csv_writer.writerow([instance_arn, "SSO", "PermissionSet", permission_set_name, json.dumps(permission_set_policies, indent=4)])

                for statement in permission_set_policies.get('Statement', []):
                    row = {
                        "UserName": "N/A",
                        "Entity": "SSO",
                        "PolicyType": "PermissionSet",
                        "Version": permission_set_policies.get("Version", ""),
                        "Action": ", ".join(statement.get("Action", [])) if isinstance(statement.get("Action", []), list) else statement.get("Action", ""),
                        "Effect": statement.get("Effect", ""),
                        "Resource": ", ".join(statement.get("Resource", [])) if isinstance(statement.get("Resource", []), list) else statement.get("Resource", ""),
                    }
                    if "Condition" in statement:
                        for condition_key, condition_value in statement["Condition"].items():
                            for sub_key, sub_value in condition_value.items():
                                field_key = f"Condition_{condition_key}_{sub_key}"
                                if field_key not in excel_writer.fieldnames:
                                    excel_writer.fieldnames.append(field_key)
                                    excel_writer.writeheader()
                                row[field_key] = sub_value
                    excel_writer.writerow(row)
