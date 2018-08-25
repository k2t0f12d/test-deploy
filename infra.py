u""" Manage infrastructure resources """
import sys
import uuid
from troposphere import Base64, ec2, GetAZs, Join, Parameter, Ref, Tags, Template
from troposphere.autoscaling import AutoScalingGroup, LaunchConfiguration, Tag
from troposphere.ec2 import InternetGateway, NetworkAcl, NetworkAclEntry, \
    PortRange, Route, RouteTable, SecurityGroup, SecurityGroupRule, \
    Subnet, SubnetNetworkAclAssociation, SubnetRouteTableAssociation, VPC, \
    VPCGatewayAttachment
from troposphere.elasticloadbalancing import LoadBalancer
from troposphere.policies import (
    AutoScalingReplacingUpdate, AutoScalingRollingUpdate, UpdatePolicy
)
import troposphere.elasticloadbalancing as elb
from botocore.exceptions import ClientError
from aws import AWS
from ami import AMI


class InfrastructureTemplate():
    u""" AWS Cloudformation Infrastructure Template """

    def __init__(self):
        u""" Infrastructure Class Contructor """
        self.aws = AWS()
        self.ami = AMI()
        self.ref_stack_id = Ref('AWS::StackId')
        self.keypair_name = 'test-deploy-keypair'
        self.ami_id = self.ami.minimal_linux_ami()
        self.deployment_bucket_prefix = 'test-deploy-bucket-'
        self.deployment_bucket_name = '{}{}'.format(self.deployment_bucket_prefix,
                                                    uuid.uuid4().hex[:12].lower())
        self.deployment_bucket_location = None

        # NOTE: Troposphere doesn't have a template feature to make KeyPairs
        #       So handle this ad-hoc for now.
        if self.keypair_doesnt_exist():
            self.create_keypair(self.keypair_name)

        if self.deploy_bucket_doesnt_exist():
            self.deployment_bucket_location = self.create_deploy_bucket(self.deployment_bucket_name)
        else:
            self.deployment_bucket_location = self.get_bucket_url(self.deployment_bucket_name)

        self.template = Template()
        self.template.add_version('2010-09-09')
        self.template.add_description(
            'AWS Cloudformation Template for autoscaled, load balance controlled EC2 service')

        self.template.add_parameter(
            Parameter('KeyName',
                      Description='Name of an existing EC2 KeyPair',
                      Default=self.keypair_name,
                      Type='String'))

        self.template.add_parameter(
            Parameter('AmdId',
                      Description='Lastest Minimal Linuix AMI',
                      Default=self.ami_id,
                      Type='String'))

        self.template.add_parameter(
            Parameter('DeployBucketName',
                      Description='Name of the deployment_bucket',
                      Default=self.deployment_bucket_name,
                      Type='String'))

        self.template.add_parameter(
            Parameter('DeployBucketLocation',
                      Description='Location of the deployment_bucket',
                      Default=self.deployment_bucket_location,
                      Type='String'))

        self.sshlocation = self.template.add_parameter(
            Parameter('SSHLocation',
                      Description='The IP address range that can be used to SSH to the EC2 instances',
                      Type='String',
                      MinLength='9',
                      MaxLength='18',
                      Default='0.0.0.0/0',
                      AllowedPattern=r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})",
                      ConstraintDescription=(
                          "must be a valid IP CIDR range of the form x.x.x.x/x.")))

        self.vpc = self.template.add_resource(
            VPC('TestDeployVpc',
                CidrBlock='10.0.0.0/16',
                Tags=Tags(Application=self.ref_stack_id)))

        self.subnet = self.template.add_resource(
            Subnet('TestDeploySubnet',
                   VpcId=Ref(self.vpc),
                   CidrBlock='10.0.0.0/24',
                   Tags=Tags(Application=self.ref_stack_id)))

        self.gateway = self.template.add_resource(
            InternetGateway('TestDeployGateway',
                            Tags=Tags(Application=self.ref_stack_id)))

        self.gatewayattach = self.template.add_resource(
            VPCGatewayAttachment('AttachGateway',
                                 VpcId=Ref(self.vpc),
                                 InternetGatewayId=Ref(self.gateway)))

        self.route_table = self.template.add_resource(
            RouteTable('RouteTable',
                       VpcId=Ref(self.vpc),
                       Tags=Tags(Application=self.ref_stack_id)))

        self.route = self.template.add_resource(
            Route('Route',
                  DependsOn='AttachGateway',
                  GatewayId=Ref('TestDeployGateway'),
                  DestinationCidrBlock='0.0.0.0/0',
                  RouteTableId=Ref(self.route_table)))

        self.subnet_route_association = self.template.add_resource(
            SubnetRouteTableAssociation('SubnetRouteTableAssociation',
                                        SubnetId=Ref(self.subnet),
                                        RouteTableId=Ref(self.route_table)))

        self.network_acl = self.template.add_resource(
            NetworkAcl('NetworkAcl',
                       VpcId=Ref(self.vpc),
                       Tags=Tags(Application=self.ref_stack_id)))

        self.inbound_private_http = self.template.add_resource(
            NetworkAclEntry('InboundHTTP',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='100',
                            Protocol='6',
                            PortRange=PortRange(To='80',
                                                From='80'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.inbound_private_https = self.template.add_resource(
            NetworkAclEntry('InboundHTTPS',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='101',
                            Protocol='6',
                            PortRange=PortRange(To='443',
                                                From='443'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.inbound_ssh = self.template.add_resource(
            NetworkAclEntry('InboundSSH',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='102',
                            Protocol='6',
                            PortRange=PortRange(To='22',
                                                From='22'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.inbound_response = self.template.add_resource(
            NetworkAclEntry('InboundResponsePorts',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='103',
                            Protocol='6',
                            PortRange=PortRange(To='65535',
                                                From='1024'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.outbound_http = self.template.add_resource(
            NetworkAclEntry('OutboundHTTP',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='100',
                            Protocol='6',
                            PortRange=PortRange(To='80',
                                                From='80'),
                            Egress='true',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.outbound_https = self.template.add_resource(
            NetworkAclEntry('OutboundHTTPS',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='101',
                            Protocol='6',
                            PortRange=PortRange(To='443',
                                                From='443'),
                            Egress='true',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.outbound_response = self.template.add_resource(
            NetworkAclEntry('OutboundResponsePorts',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='102',
                            Protocol='6',
                            PortRange=PortRange(To='65535',
                                                From='1024'),
                            Egress='true',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.subnet_network_association = self.template.add_resource(
            SubnetNetworkAclAssociation('SubnetNetworkACLAssociation',
                                        SubnetId=Ref(self.subnet),
                                        NetworkAclId=Ref(self.network_acl)))

        self.instance_security_group = self.template.add_resource(
            SecurityGroup('InstanceSecurityGroup',
                          GroupDescription='Enable SSH access via port 22',
                          SecurityGroupIngress=[
                              SecurityGroupRule(
                                  IpProtocol='tcp',
                                  FromPort='22',
                                  ToPort='22',
                                  CidrIp=Ref(self.sshlocation)),
                              SecurityGroupRule(
                                  IpProtocol='tcp',
                                  FromPort='80',
                                  ToPort='80',
                                  CidrIp='0.0.0.0/0')],
                          VpcId=Ref(self.vpc)))

        self.launch_configuration = self.template.add_resource(
            LaunchConfiguration('LaunchConfiguration',
                                UserData=Base64(Join('', [
                                    "#!/bin/bash\n",
                                    "",
                                    "cfn-signal -e 0",
                                    "    --resource AutoScalingGroup",
                                    "    --stack ", Ref("AWS::StackName"),
                                    "    --region ", Ref("AWS::Region"), "\n"
                                ])),
                                ImageId=Ref('AmiId'),
                                KeyName=Ref('KeyName'),
                                BlockDeviceMappings=[
                                    ec2.BlockDeviceMapping(
                                        DeviceName="/dev/sda1",
                                        Ebs=ec2.EBSBlockDevice(
                                            VolumeSize="8"
                                        )
                                    )
                                ],
                                SecurityGroups=['InstanceSecurityGroup'],
                                InstanceType="m1.small"))

        self.load_balancer = self.template.add_resource(LoadBalancer(
            "LoadBalancer",
            ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
                Enabled=True,
                Timeout=120,
            ),
            Subnets=['TestDeploySubnet'],
            HealthCheck=elb.HealthCheck(
                Target='HTTP:80/',
                HealthyThreshold='5',
                UnhealthyThreshold='2',
                Interval='20',
                Timeout='15'
            ),
            Listeners=[
                elb.Listener(
                    LoadBalancerPort='443',
                    InstancePort='80',
                    Protocol='HTTPS',
                    InstanceProtocol='HTTP',
                    SSLCertificateId='SSLCertificateId'
                )
            ],
            CrossZone=True,
            SecurityGroups=['LoadBalancerSecurityGroup'],
            LoadBalancerName='api-lb',
            Scheme='internet-facing'))

        self.auto_scaling_group = self.template.add_resource(
            AutoScalingGroup(
                "AutoscalingGroup",
                DesiredCapacity=1,
                Tags=[
                    Tag("Environment", 'EnvType', True)
                ],
                LaunchConfigurationName=Ref(self.launch_configuration),
                MinSize=1,
                MaxSize=2,
                VPCZoneIdentifier=[Ref(self.subnet)],
                LoadBalancerNames=[Ref(self.load_balancer)],
                AvailabilityZones=[GetAZs()],
                HealthCheckType='EC2',
                UpdatePolicy=UpdatePolicy(
                    AutoScalingReplacingUpdate=AutoScalingReplacingUpdate(
                        WillReplace=True,
                    ),
                    AutoScalingRollingUpdate=AutoScalingRollingUpdate(
                        PauseTime='PT5M',
                        MinInstancesInService="1",
                        MaxBatchSize='1',
                        WaitOnResourceSignals=True
                    )
                )
            ))

    @staticmethod
    def get_bucket_url(bucket_name):
        u""" Generates the bucket location """
        return 'https://{}.s3.amazonaws.com/'.format(bucket_name)

    def keypair_doesnt_exist(self):
        u""" Check to see if EC2 keypair exists """
        client = self.aws.get_client('ec2')
        try:
            client.describe_key_pairs(KeyNames=[self.keypair_name])
        except ClientError:
            return True
        return False

    # NOTE: This prints the key material to console
    #       A much more robust handling would be recommended here
    def create_keypair(self, keypair_name):
        u""" Create a keypair resource """
        client = self.aws.get_client('ec2')
        try:
            res = client.create_key_pair(KeyName=keypair_name)
            print(res['KeyMaterial'])
        except ClientError as ex:
            sys.exit(ex)

    def deploy_bucket_doesnt_exist(self):
        u""" Check to see if the deployment bucket exists """
        client = self.aws.get_client('s3')
        try:
            res = client.list_buckets()
            for bucket in res['Buckets']:
                if self.deployment_bucket_prefix in bucket['Name']:
                    self.delpoyment_bucket_name = bucket['Name']
                    return False
            return True
        except ClientError as ex:
            sys.exit(ex)

    def create_deploy_bucket(self, bucket_name):
        u""" Create static deployment bucket """
        client = self.aws.get_client('s3')
        try:
            res = client.create_bucket(ACL='private',
                                       Bucket=bucket_name,
                                       CreateBucketConfiguration=\
                                       {'LocationConstraint': self.aws.session.region_name})
            print('Create Bucket: {}'.format(res))
            return res['Location']
        except ClientError as ex:
            sys.exit(ex)

    def cleanup(self):
        u""" Cleanup static resources """
        self.destroy_deploy_bucket()
        self.destroy_ec2_keypair(self.keypair_name)

    def destroy_deploy_bucket(self):
        u""" Destroy static deployment bucket(s) """
        client = self.aws.get_client('s3')
        buckets = client.list_buckets()
        for bucket in buckets['Buckets']:
            objects = client.list_objects_v2(Bucket=bucket['Name'])
            while True:
                if 'Contents' not in objects:
                    break
                for s3_object in objects['Contents']:
                    if 'test-deploy-bucket-' in s3_object['Key']:
                        try:
                            client.delete_object(Bucket=bucket['Name'],
                                                 Key=s3_object['Key'])
                        except ClientError as ex:
                            print(ex)
                            continue
                if objects['IsTruncated']:
                    token = objects['ContinuationToken']
                    objects = client.list_objects_v2(bucket['Name'],
                                                     ContinuationToken=token)
                else:
                    break
            result = client.delete_bucket(Bucket=bucket['Name'])
            print(result)

    def destroy_ec2_keypair(self, keypair):
        u""" Destroy static ec2 keypair resources """
        client = self.aws.get_client('ec2')
        try:
            client.delete_key_pair(KeyName=keypair)
        except ClientError as ex:
            print(ex)
            sys.exit()

    def print_template(self, output='yaml'):
        u""" Dump Cloudformation Template """
        if 'yaml' not in output:
            print(self.template.to_json())
        else:
            print(self.template.to_yaml())

    def generate_template(self, output='yaml'):
        u""" Return the Cloudformation Template Body """
        if 'yaml' not in output:
            return self.template.to_json()
        return self.template.to_yaml()
