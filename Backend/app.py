from flask import Flask, jsonify
import boto3

app = Flask(__name__)

def get_vpcs():
    ec2 = boto3.client('ec2')
    response = ec2.describe_vpcs()
    return response['Vpcs']

def get_subnets():
    ec2 = boto3.client('ec2')
    response = ec2.describe_subnets()
    return response['Subnets']

def get_security_groups():
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups()
    return response['SecurityGroups']

def get_instances():
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances()
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances.append(instance)
    return instances

def map_network():
    network_map = {
        'VPCs': [],
        'Subnets': [],
        'SecurityGroups': [],
        'Instances': []
    }

    # Get VPCs
    vpcs = get_vpcs()
    for vpc in vpcs:
        network_map['VPCs'].append({
            'VpcId': vpc['VpcId'],
            'State': vpc['State'],
            'CidrBlock': vpc['CidrBlock'],
            'IsDefault': vpc['IsDefault']
        })

    # Get Subnets
    subnets = get_subnets()
    for subnet in subnets:
        network_map['Subnets'].append({
            'SubnetId': subnet['SubnetId'],
            'VpcId': subnet['VpcId'],
            'State': subnet['State'],
            'CidrBlock': subnet['CidrBlock'],
            'AvailabilityZone': subnet['AvailabilityZone']
        })

    # Get Security Groups
    security_groups = get_security_groups()
    for sg in security_groups:
        network_map['SecurityGroups'].append({
            'GroupId': sg['GroupId'],
            'GroupName': sg['GroupName'],
            'Description': sg['Description'],
            'VpcId': sg.get('VpcId', 'N/A')
        })

    # Get Instances
    instances = get_instances()
    for instance in instances:
        network_map['Instances'].append({
            'InstanceId': instance['InstanceId'],
            'InstanceType': instance['InstanceType'],
            'State': instance['State']['Name'],
            'VpcId': instance['VpcId'],
            'SubnetId': instance['SubnetId'],
            'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
            'PublicIpAddress': instance.get('PublicIpAddress', 'N/A')
        })

    return network_map

@app.route('/network-map', methods=['GET'])
def network_map():
    network_data = map_network()
    return jsonify(network_data)

if __name__ == '__main__':
    app.run(debug=True)
