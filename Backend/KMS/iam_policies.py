import boto3
import json
from utils import CustomJSONEncoder

# get the policy documents from the ARN
def get_policy_document(iam, policy_arn):
    version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    policy_document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']['Document']
    return policy_document


def list_user_policies(iam, user_name, csv_writer, excel_writer):
    attached_user_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    if attached_user_policies:
        for policy in attached_user_policies:
            policy_arn = policy['PolicyArn']
            policy_document = get_policy_document(iam, policy_arn)
            csv_writer.writerow([user_name, "User", "Attached", policy['PolicyName'], json.dumps(policy_document, indent=4)])
            for statement in policy_document.get('Statement', []):
                row = {
                    "UserName": user_name,
                    "Entity": "User",
                    "PolicyType": "Attached",
                    "Version": policy_document.get("Version", ""),
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
    else:
        csv_writer.writerow([user_name, "User", "Attached", "No attached user policies", ""])

    inline_user_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
    if inline_user_policies:
        for policy_name in inline_user_policies:
            policy_document = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
            csv_writer.writerow([user_name, "User", "Inline", policy_name, json.dumps(policy_document, indent=4)])
            for statement in policy_document.get('Statement', []):
                row = {
                    "UserName": user_name,
                    "Entity": "User",
                    "PolicyType": "Inline",
                    "Version": policy_document.get("Version", ""),
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
    else:
        csv_writer.writerow([user_name, "User", "Inline", "No inline user policies", ""])

def list_group_policies(iam, group_name, user_name, csv_writer, excel_writer):
    attached_group_policies = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    if attached_group_policies:
        for policy in attached_group_policies:
            policy_arn = policy['PolicyArn']
            policy_document = get_policy_document(iam, policy_arn)
            csv_writer.writerow([user_name, f"Group: {group_name}", "Attached", policy['PolicyName'], json.dumps(policy_document, indent=4)])
            for statement in policy_document.get('Statement', []):
                row = {
                    "UserName": user_name,
                    "Entity": f"Group: {group_name}",
                    "PolicyType": "Attached",
                    "Version": policy_document.get("Version", ""),
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
    else:
        csv_writer.writerow([user_name, f"Group: {group_name}", "Attached", "No attached group policies", ""])

    inline_group_policies = iam.list_group_policies(GroupName=group_name)['PolicyNames']
    if inline_group_policies:
        for policy_name in inline_group_policies:
            policy_document = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            csv_writer.writerow([user_name, f"Group: {group_name}", "Inline", policy_name, json.dumps(policy_document, indent=4)])
            for statement in policy_document.get('Statement', []):
                row = {
                    "UserName": user_name,
                    "Entity": f"Group: {group_name}",
                    "PolicyType": "Inline",
                    "Version": policy_document.get("Version", ""),
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
    else:
        csv_writer.writerow([user_name, f"Group: {group_name}", "Inline", "No inline group policies", ""])

def list_role_policies(iam, role_name, user_name, csv_writer, excel_writer):
    attached_role_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    if attached_role_policies:
        for policy in attached_role_policies:
            policy_arn = policy['PolicyArn']
            policy_document = get_policy_document(iam, policy_arn)
            csv_writer.writerow([user_name, f"Role: {role_name}", "Attached", policy['PolicyName'], json.dumps(policy_document, indent=4)])
            for statement in policy_document.get('Statement', []):
                row = {
                    "UserName": user_name,
                    "Entity": f"Role: {role_name}",
                    "PolicyType": "Attached",
                    "Version": policy_document.get("Version", ""),
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
    else:
        csv_writer.writerow([user_name, f"Role: {role_name}", "Attached", "No attached role policies", ""])

    inline_role_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    if inline_role_policies:
        for policy_name in inline_role_policies:
            policy_document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            csv_writer.writerow([user_name, f"Role: {role_name}", "Inline", policy_name, json.dumps(policy_document, indent=4)])
            for statement in policy_document.get('Statement', []):
                row = {
                    "UserName": user_name,
                    "Entity": f"Role: {role_name}",
                    "PolicyType": "Inline",
                    "Version": policy_document.get("Version", ""),
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
    else:
        csv_writer.writerow([user_name, f"Role: {role_name}", "Inline", "No inline role policies", ""])
