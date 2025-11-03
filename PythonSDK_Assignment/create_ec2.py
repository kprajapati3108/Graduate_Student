#!/usr/bin/env python3
import boto3
import botocore
import json
import os
from datetime import datetime, timezone
from urllib.request import urlopen

REGION = os.getenv("AWS_REGION", "us-east-2")
KEY_NAME = os.getenv("KEY_NAME", "my-key-pair")
SECURITY_GROUP_NAME = os.getenv("SECURITY_GROUP_NAME", "ITMO-444-544-lab-security-group")
INSTANCE_TYPE = os.getenv("INSTANCE_TYPE", "t3.micro")
TAG_NAME = os.getenv("TAG_NAME", "ITMO-444-544-Web-Server")
KEY_FILE = os.getenv("KEY_FILE", f"{KEY_NAME}.pem")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")
MY_IP_CIDR = os.getenv("MY_IP_CIDR")
MY_IPV6_CIDR = os.getenv("MY_IPV6_CIDR")

def jprint(obj):
    print(json.dumps(obj, indent=2, default=str))

def _get(url):
    try:
        return urlopen(url, timeout=8).read().decode().strip()
    except Exception:
        return None

def get_ip_cidrs():
    v4 = MY_IP_CIDR
    v6 = MY_IPV6_CIDR
    if not v4:
        ip4 = _get("https://ipv4.icanhazip.com")
        if not ip4:
            ip4 = _get("https://ifconfig.me/ip")
        if ip4:
            v4 = f"{ip4}/32"
    if not v6:
        ip6 = _get("https://ipv6.icanhazip.com")
        if ip6:
            v6 = f"{ip6}/128"
    if not v4 and not v6:
        entered4 = input("Enter your IPv4 CIDR (e.g., 203.0.113.5/32) or leave blank: ").strip()
        v4 = entered4 if entered4 else None
        entered6 = input("Enter your IPv6 CIDR (e.g., 2001:db8::1234/128) or leave blank: ").strip()
        v6 = entered6 if entered6 else None
        if not v4 and not v6:
            v4 = "0.0.0.0/0"
    return v4, v6

def ensure_key_pair(ec2_client):
    try:
        ec2_client.describe_key_pairs(KeyNames=[KEY_NAME])
        print(f"Key pair '{KEY_NAME}' already exists.")
        return None
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "InvalidKeyPair.NotFound":
            raise
    resp = ec2_client.create_key_pair(KeyName=KEY_NAME, KeyType='ed25519')
    material = resp["KeyMaterial"]
    key_path = os.path.join(OUTPUT_DIR, KEY_FILE)
    with open(key_path, "w") as f:
        f.write(material)
    os.chmod(key_path, 0o400)
    print(f"Saved key to {key_path}.")
    return key_path

def ensure_security_group(ec2_client, vpc_id, v4cidr, v6cidr):
    resp = ec2_client.describe_security_groups(Filters=[
        {"Name": "group-name", "Values": [SECURITY_GROUP_NAME]},
        {"Name": "vpc-id", "Values": [vpc_id]},
    ])
    if resp["SecurityGroups"]:
        sg = resp["SecurityGroups"][0]
        sg_id = sg["GroupId"]
        print(f"Using SG: {sg_id}")
    else:
        created = ec2_client.create_security_group(
            GroupName=SECURITY_GROUP_NAME,
            Description="Security group for lab",
            VpcId=vpc_id
        )
        sg_id = created["GroupId"]
        print(f"Created SG: {sg_id}")
    existing = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    existing_permissions = existing.get("IpPermissions", [])
    has22 = any(p.get("IpProtocol") == "tcp" and p.get("FromPort") == 22 and p.get("ToPort") == 22 for p in existing_permissions)
    has80 = any(p.get("IpProtocol") == "tcp" and p.get("FromPort") == 80 and p.get("ToPort") == 80 for p in existing_permissions)
    perms = []
    if not has22:
        if v4cidr:
            perms.append({"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":v4cidr}]})
        if v6cidr:
            perms.append({"IpProtocol":"tcp","FromPort":22,"ToPort":22,"Ipv6Ranges":[{"CidrIpv6":v6cidr}]})
    if not has80:
        perms.append({"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]})
        perms.append({"IpProtocol":"tcp","FromPort":80,"ToPort":80,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]})
    if perms:
        try:
            ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=perms)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                raise
    return sg_id

def get_default_vpc_id(ec2_client):
    vpcs = ec2_client.describe_vpcs(Filters=[{"Name":"isDefault","Values":["true"]}])["Vpcs"]
    return vpcs[0]["VpcId"]

def latest_ubuntu_2204_ami(ec2_client):
    imgs = ec2_client.describe_images(
        Owners=["099720109477"],
        Filters=[
            {"Name":"name","Values":["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]},
            {"Name":"architecture","Values":["x86_64"]},
            {"Name":"virtualization-type","Values":["hvm"]},
        ]
    )["Images"]
    imgs.sort(key=lambda x: x["CreationDate"])
    return imgs[-1]["ImageId"]

USER_DATA = r'''#cloud-config
package_update: true
packages:
  - nginx
runcmd:
  - systemctl enable nginx
  - systemctl start nginx
  - printf "<html><body><h1>Welcome to My NGINX Site!</h1></body></html>" > /var/www/html/index.html
'''

def main():
    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting create flow in region {REGION}...")
    session = boto3.Session(region_name=REGION)
    ec2_client = session.client("ec2")
    ensure_key_pair(ec2_client)
    vpc_id = get_default_vpc_id(ec2_client)
    v4cidr, v6cidr = get_ip_cidrs()
    sg_id = ensure_security_group(ec2_client, vpc_id, v4cidr, v6cidr)
    ami_id = latest_ubuntu_2204_ami(ec2_client)
    run = ec2_client.run_instances(
        ImageId=ami_id,
        InstanceType=INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        KeyName=KEY_NAME,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":TAG_NAME}]}],
        UserData=USER_DATA
    )
    instance_id = run["Instances"][0]["InstanceId"]
    ec2_client.get_waiter("instance_running").wait(InstanceIds=[instance_id])
    desc = ec2_client.describe_instances(InstanceIds=[instance_id])
    public_ip = desc["Reservations"][0]["Instances"][0].get("PublicIpAddress")
    ec2_client.get_waiter("instance_status_ok").wait(InstanceIds=[instance_id])
    with open(os.path.join(OUTPUT_DIR, "instance_id.txt"), "w") as f:
        f.write(instance_id + "\n")
    with open(os.path.join(OUTPUT_DIR, "instance_ip.txt"), "w") as f:
        f.write((public_ip or "") + "\n")
    jprint({"InstanceId":instance_id,"PublicIp":public_ip,"Region":REGION,"SecurityGroupId":sg_id,"KeyName":KEY_NAME,"AMI":ami_id,"URL":f"http://{public_ip}" if public_ip else None})

if __name__ == "__main__":
    main()
