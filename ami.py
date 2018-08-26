u""" Manage AWS AMI resources """
import sys
from datetime import datetime, timezone
from dateutil.parser import parse
from botocore.exceptions import ClientError
from aws import AWS


class AMI():
    u""" Manage AWS AMI Resources """
    def __init__(self):
        u""" AMI Class contructor """
        self.aws = AWS()

    def minimal_linux_ami(self):
        u""" Get Minimal AWS Linux AMI ID """
        client = self.aws.get_client('ec2')
        try:
            res = client.describe_images(Owners=['self', '099720109477'],
                                         Filters=[
                                             {
                                                 'Name': 'virtualization-type',
                                                 'Values': ['hvm']
                                             },
                                             {
                                                 'Name': 'root-device-type',
                                                 'Values': ['ebs']
                                             },
                                             {
                                                 'Name': 'architecture',
                                                 'Values': ['x86_64']
                                             },
                                             {
                                                 'Name': 'description',
                                                 'Values': ['Canonical, Ubuntu, 16.04 LTS, amd64 xenial image*']
                                             }])
        except ClientError as ex:
            print(ex)
            sys.exit()
        timestep = None
        current_time = datetime.now(timezone.utc)
        ami_id = None
        for image in res['Images']:
            if timestep:
                create_time = parse(image['CreationDate'])
                current_timestep = current_time - create_time
                if current_timestep < timestep:
                    timestep = current_timestep
                    ami_id = image['ImageId']
            else:
                create_time = parse(image['CreationDate'])
                timestep = current_time - create_time
                ami_id = image['ImageId']
        return ami_id
