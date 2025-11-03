#!/usr/bin/env python3
import boto3
import botocore
import os
import sys

REGION = os.getenv("AWS_REGION", "us-east-2")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", ".")

def read_instance_id():
    path = os.path.join(OUTPUT_DIR, "instance_id.txt")
    if not os.path.exists(path):
        print("instance_id.txt not found.")
        sys.exit(1)
    with open(path) as f:
        return f.read().strip()

def main():
    instance_id = read_instance_id()
    ec2 = boto3.client("ec2", region_name=REGION)
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id])
    except botocore.exceptions.ClientError:
        pass
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id])
    except botocore.exceptions.ClientError:
        pass
    print("Instance terminated successfully.")

if __name__ == "__main__":
    main()

