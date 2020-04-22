
# from boto3_type_annotations.s3 import Client, ServiceResource
# from boto3_type_annotations.s3.waiter import BucketExists
# from boto3_type_annotations.s3.paginator import ListObjectsV2

import logging
import boto3
from botocore.exceptions import ClientError
import json
from pathlib import Path
import os
from boto3.s3.transfer import TransferConfig
import threading
import sys
import math

# client: Client = boto3.client('s3')
# client.create_bucket(Bucket='s3-practices1', CreateBucketConfiguration={'LocationConstraint':'ap-south-1'})
#
# resource: ServiceResource = boto3.resource('s3')
# bucket = resource.Bucket('testkey')
# bucket.create()
class ProgressPercentage(object):
    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write(
                "\r%s  %s / %s  (%.2f%%)" % (
                    self._filename, self._seen_so_far, self._size, percentage
                )
            )
            sys.stdout.flush()

def create_bucket(bucket_name, region=None):
    """Create an S3 bucket in a specified region

    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1).

    :param bucket_name: Bucket to create
    :param region: String region to create bucket in, e.g., 'us-west-2'
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        if region is None:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client = boto3.client('s3', region_name=region)
            location = {'LocationConstraint': region}
            s3_client.create_bucket(Bucket=bucket_name,
                                    CreateBucketConfiguration=location)
    except ClientError as e:
        logging.error(e)
        return False
    return True

def list_bucket():
    s3 = boto3.client('s3')
    response = s3.list_buckets()

    # Output the bucket names
    print('Existing buckets:')
    for bucket in response['Buckets']:
        print(f'  {bucket["Name"]}')

def get_bucketpolicy(bucket_name):
    s3 = boto3.client('s3')
    response= s3.get_bucket_policy(Bucket=bucket_name)
    return response

def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True

def create_bucket_policy():
    s3_client = boto3.client('s3')
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": ["arn:aws:s3:::s3-practices1/*"]
            }
        ]
    }
    policy_string = json.dumps(bucket_policy)
    return s3_client.put_bucket_policy(
        Bucket='s3-practices1',
        Policy=policy_string
    )
def delete_bucket(bucket_name):
    s3_client = boto3.client('s3')
    return s3_client.delete_bucket(Bucket=bucket_name)

def server_side_encrypt_bucket(bucket_name):
    s3_client = boto3.client('s3')
    s3_client.put_bucket_encryption(
Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules':[
                {
                    'ApplyServerSideEncryptionByDefault':{
                        'SSEAlgorithm':'AES256'
                    }
                }
            ]
        }

    )

def update_bucket_policy(bucket_name):
    s3_client = boto3.client('s3')
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPerm",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ['s3:DeleteObject',
                           's3:GetObject',
                           's3:PutObject'
                           ],
                "Resource": 'arn:aws:s3:::'+bucket_name+'/*'
            }
        ]

    }
    policy_string = json.dumps(bucket_policy)
    return s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=policy_string
    )

def readBucketobject():
    s3client = boto3.client('s3')
    bucket = 's3-practices1'
    # Read data from s3 bucket specific folder
    prefix = 'multipart_files/'
    theobjects = s3client.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter='/')
    for object in theobjects['Contents']:
        print(object['Key'])

#Copy object from one bucket to another bucket
def Copy_object_to_otherBucket():
    s3client = boto3.resource('s3')
    bucket = 's3-practices1'
    copy_source = {
        'Bucket': 's3-practices1',
        'Key': 'pythoncode.txt'
    }
    bucket = s3client.Bucket('s3-practices2')
    bucket.copy(copy_source, 'pythoncode.txt')

#enable versioning on buckets
def version_bucket_files(bucket_name):
    s3client = boto3.client('s3')
    s3client.put_bucket_versioning(
        Bucket= bucket_name,
        VersioningConfiguration={
            'Status':'Enabled'
        }
    )

# upload different version of same file
def upload_a_new_version(bucket_name):
    data_folder = Path(r"C:\Users\xxx\PycharmProjects")
    file_to_upload = str(data_folder)+'\pythoncode.txt'
    s3_client = boto3.client('s3')
    return s3_client.upload_file(file_to_upload, bucket_name, 'pythoncode.txt')
 # return response


def s3_resource():
    s3 = boto3.resource('s3')
    return s3

def upload_large_object(bucket_name):
    config = TransferConfig(multipart_threshold=1024 * 25, max_concurrency=10,
                            multipart_chunksize=1024 * 25, use_threads=True)
    data_folder = Path("C:\xxx.Net")
    file_path = str(data_folder) + '/azure.zip'
    key_path='multipart_files/azure.zip'
    s3_resource().meta.client.upload_file(file_path, bucket_name, key_path,
                                          ExtraArgs={'ACL': 'public-read', 'ContentType': 'application/zip'},
                                          Config=config,
                                          Callback=ProgressPercentage(file_path))


# create_bucket('s3-practices2','ap-south-1')
# list_bucket()

# upload_large_object('s3-practices1')
# data_folder = Path("C:\Saurav.Net")
# file_to_upload = str(data_folder)+'/azure.zip'
# file_path= os.path.dirname(__file__)+'/pythoncode.txt'
# upload_file(file_to_upload,'s3-practices1','pythoncode.txt')
# print(delete_bucket('s3-practices2'))
# readBucketobject()
# Copy_object_to_otherBucket()


# print(create_bucket_policy())
# server_side_encrypt_bucket('s3-practices1')
# version_bucket_files('s3-practices1')

# print(upload_a_new_version('s3-practices1'))
