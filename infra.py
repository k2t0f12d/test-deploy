u""" Manage infrastructure resources """
import os
import sys
import uuid
import zipfile
from troposphere import Base64, Join, Parameter, Ref, Tags, Template
from troposphere.ec2 import Instance, InternetGateway, NetworkAcl, \
    NetworkAclEntry, NetworkInterfaceProperty, PortRange, Route, RouteTable, \
    SecurityGroup, SecurityGroupRule, Subnet, SubnetNetworkAclAssociation, \
    SubnetRouteTableAssociation, VPC, VPCGatewayAttachment
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
        self.ami_id = self.ami.minimal_linux_ami()

        # NOTE: Troposphere doesn't have a template feature to make KeyPairs
        #       So handle this ad-hoc for now.
        self.keypair_name = 'test-deploy-keypair'
        if self.keypair_doesnt_exist():
            self.create_keypair(self.keypair_name)

        self.deployment_bucket_prefix = 'test-deploy-bucket-'
        self.deployment_bucket_name = '{}{}'.format(self.deployment_bucket_prefix,
                                                    uuid.uuid4().hex[:12].lower())
        self.deployment_bucket_location = None
        if self.deploy_bucket_doesnt_exist():
            self.deployment_bucket_location = self.create_deploy_bucket(self.deployment_bucket_name)
        else:
            self.deployment_bucket_location = self.get_bucket_url(self.deployment_bucket_name)

        self.server_certificate_name = 'test-deploy-certificate'
        self.server_certificate_arn = None
        if self.server_certificate_doesnt_exist():
            self.server_certificate_arn = self.upload_server_certificate()

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
            Parameter('AmiId',
                      Description='Lastest Minimal Linux AMI',
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

        self.template.add_parameter(
            Parameter('ServerCertificateArn',
                      Description='Certificate ARN for the Load Balancer',
                      Default=self.server_certificate_arn,
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
                                        RouteTableId=Ref(self.route_table),
                                        DependsOn=['TestDeploySubnet', 'RouteTable']))

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

        self.inbound_private_http_alt = self.template.add_resource(
            NetworkAclEntry('InboundHTTPAlt',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='101',
                            Protocol='6',
                            PortRange=PortRange(To='8000',
                                                From='8000'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.inbound_private_https = self.template.add_resource(
            NetworkAclEntry('InboundHTTPS',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='102',
                            Protocol='6',
                            PortRange=PortRange(To='443',
                                                From='443'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.inbound_ssh = self.template.add_resource(
            NetworkAclEntry('InboundSSH',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='103',
                            Protocol='6',
                            PortRange=PortRange(To='22',
                                                From='22'),
                            Egress='false',
                            RuleAction='allow',
                            CidrBlock='0.0.0.0/0'))

        self.inbound_response = self.template.add_resource(
            NetworkAclEntry('InboundResponsePorts',
                            NetworkAclId=Ref(self.network_acl),
                            RuleNumber='104',
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
                                        NetworkAclId=Ref(self.network_acl),
                                        DependsOn=['TestDeploySubnet', 'NetworkAcl']))

        self.instance_security_group = self.template.add_resource(
            SecurityGroup('InstanceSecurityGroup',
                          GroupDescription='Open all ports',
                          SecurityGroupIngress=[
                              SecurityGroupRule(
                                  IpProtocol='tcp',
                                  FromPort='22',
                                  ToPort='22',
                                  CidrIp='0.0.0.0/0'),
                              SecurityGroupRule(
                                  IpProtocol='tcp',
                                  FromPort='1024',
                                  ToPort='65535',
                                  CidrIp='0.0.0.0/0')
                          ],
                          SecurityGroupEgress=[
                              SecurityGroupRule(
                                  IpProtocol='tcp',
                                  FromPort='1',
                                  ToPort='65535',
                                  CidrIp='0.0.0.0/0')],
                          VpcId=Ref(self.vpc)))

        self.instance = self.template.add_resource(
            Instance(
                'TestDeployInstance',
                ImageId=Ref('AmiId'),
                InstanceType='t2.micro',
                KeyName=Ref('KeyName'),
                NetworkInterfaces=[
                    NetworkInterfaceProperty(
                        GroupSet=[
                            Ref('InstanceSecurityGroup')],
                        AssociatePublicIpAddress='true',
                        DeviceIndex='0',
                        DeleteOnTermination='true',
                        SubnetId=Ref('TestDeploySubnet'))],
                UserData=Base64(Join('', [
                    "#!/bin/bash\n",
                    "apt-get update\n",
                    "apt-get -y install python python-pip python-setuptools\n",
                    "mkdir aws-cfn-bootstrap-latest\n",
                    "curl https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz | tar xz -C aws-cfn-bootstrap-latest --strip-components 1\n",
                    "easy_install aws-cfn-bootstrap-latest\n",
                    "/usr/local/bin/cfn-init --stack ", {"Ref":"AWS::StackName"}, " --resource TestDeployInstance", " --region ", {"Ref": "AWS::Region"}, "\n",
                    "/usr/local/bin/cfn-signal --exit-code $? '", {"Ref" : "WaitHandle"}, "'\n"
                    "\n",
                    "python -m SimpleHTTPServer 8000 2>&1 >/dev/null &\n",
                ])),
                DependsOn=['InstanceSecurityGroup', 'TestDeploySubnet'],
                Tags=Tags(
                    Application=self.ref_stack_id)))

        # self.load_balancer_security_group = self.template.add_resource(
        #     SecurityGroup('LoadBalancerSecurityGroup',
        #                   GroupDescription='Open all ports',
        #                   SecurityGroupIngress=[
        #                       SecurityGroupRule(
        #                           IpProtocol='tcp',
        #                           FromPort='1',
        #                           ToPort='65535',
        #                           CidrIp='0.0.0.0/0')],
        #                   SecurityGroupEgress=[
        #                       SecurityGroupRule(
        #                           IpProtocol='tcp',
        #                           FromPort='1',
        #                           ToPort='65535',
        #                           CidrIp='0.0.0.0/0')],
        #                   VpcId=Ref(self.vpc)))

        # self.launch_configuration = self.template.add_resource(
        #     LaunchConfiguration('LaunchConfiguration',
        #                         AssociatePublicIpAddress=True,
        #                         UserData=Base64(Join('', [
        #                             "#!/bin/bash\n",
        #                             "sudo pip install ansible\n",
        #                             "sudo pip install SimpleHTTPServer\n",
        #                             "python -m SimpleHTTPServer 8000 2>&1 >/dev/null &\n",
        #                             "cfn-signal -e 0",
        #                             "    --resource AutoScalingGroup",
        #                             "    --stack ", Ref("AWS::StackName"),
        #                             "    --region ", Ref("AWS::Region"), "\n"
        #                         ])),
        #                         ImageId=Ref('AmiId'),
        #                         KeyName=Ref('KeyName'),
        #                         BlockDeviceMappings=[
        #                             ec2.BlockDeviceMapping(
        #                                 DeviceName="/dev/sda1",
        #                                 Ebs=ec2.EBSBlockDevice(
        #                                     VolumeSize="8"
        #                                 )
        #                             )
        #                         ],
        #                         SecurityGroups=[Ref('InstanceSecurityGroup')],
        #                         InstanceType="t2.micro",
        #                         DependsOn='InstanceSecurityGroup'))

        # self.load_balancer = self.template.add_resource(
        #     LoadBalancer(
        #         "LoadBalancer",
        #         ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
        #             Enabled=True,
        #             Timeout=120,
        #         ),
        #         Subnets=[Ref('TestDeploySubnet')],
        #         HealthCheck=elb.HealthCheck(
        #             Target='HTTP:8000/',
        #             HealthyThreshold='10',
        #             UnhealthyThreshold='10',
        #             Interval='300',
        #             Timeout='60'
        #         ),
        #         Listeners=[
        #             elb.Listener(
        #                 LoadBalancerPort='443',
        #                 InstancePort='8000',
        #                 Protocol='HTTPS',
        #                 InstanceProtocol='HTTP',
        #                 SSLCertificateId=Ref('ServerCertificateArn')
        #             ),
        #             elb.Listener(
        #                 LoadBalancerPort='22',
        #                 InstancePort='22',
        #                 Protocol='TCP',
        #                 InstanceProtocol='TCP'
        #             )
        #         ],
        #         CrossZone=True,
        #         SecurityGroups=[Ref('LoadBalancerSecurityGroup')],
        #         LoadBalancerName='api-lb',
        #         Scheme='internet-facing',
        #         DependsOn=['LoadBalancerSecurityGroup',
        #                    'TestDeploySubnet']))

        # self.auto_scaling_group = self.template.add_resource(
        #     AutoScalingGroup(
        #         "AutoscalingGroup",
        #         DesiredCapacity=1,
        #         Tags=[
        #             Tag("Environment", 'EnvType', True)
        #         ],
        #         LaunchConfigurationName=Ref(self.launch_configuration),
        #         MinSize=1,
        #         MaxSize=2,
        #         VPCZoneIdentifier=[Ref(self.subnet)],
        #         LoadBalancerNames=[Ref(self.load_balancer)],
        #         HealthCheckType='EC2',
        #         UpdatePolicy=UpdatePolicy(
        #             AutoScalingReplacingUpdate=AutoScalingReplacingUpdate(
        #                 WillReplace=True,
        #             ),
        #             AutoScalingRollingUpdate=AutoScalingRollingUpdate(
        #                 PauseTime='PT5M',
        #                 MinInstancesInService="1",
        #                 MaxBatchSize='1',
        #                 WaitOnResourceSignals=True
        #             )
        #         )
        #     ))

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

    def create_keypair(self, keypair_name):
        u""" Create a keypair resource """
        client = self.aws.get_client('ec2')
        try:
            res = client.create_key_pair(KeyName=keypair_name)
            print(res['KeyMaterial'])
            open('ansible/test-deploy.pem', 'w').write(res['KeyMaterial'])
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

    def server_certificate_doesnt_exist(self):
        u""" Check for the presence of the server certificate """
        client = self.aws.get_client('iam')
        res = client.list_server_certificates()
        for cert in res['ServerCertificateMetadataList']:
            if self.server_certificate_name in cert['ServerCertificateName']:
                self.server_certificate_arn = cert['Arn']
                return False
        return True

    def upload_server_certificate(self):
        u""" Upload server certificate to AWS ACM """
        client = self.aws.get_client('iam')
        certificate = open('cert.pem', 'r').read()
        private_key = open('key.pem', 'r').read()
        try:
            res = client.upload_server_certificate(ServerCertificateName=self.server_certificate_name,
                                                   CertificateBody=certificate,
                                                   PrivateKey=private_key)
            from pprint import pprint as pp
            pp('Uploaded: {}'.format(res))
            return res['ServerCertificateMetadata']['Arn']
        except ClientError as ex:
            print(ex)
            sys.exit()

    def cleanup(self):
        u""" Cleanup static resources """
        self.destroy_deploy_bucket()
        self.destroy_ec2_keypair(self.keypair_name)
        self.delete_server_certificate(self.server_certificate_name)

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

    def delete_server_certificate(self, certificate_name):
        u""" Remove certificate from AWS Certificate Manager """
        client = self.aws.get_client('iam')
        try:
            client.delete_server_certificate(ServerCertificateName=certificate_name)
        except ClientError as ex:
            print(ex)

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

    def prepare_payload(self):
        u""" Collect all payload files in a zip archive """
        if os.path.isfile('test-deploy-files.zip'):
            os.remove('test-deploy-files.zip')
        zipf = zipfile.ZipFile('test-deploy-files.zip', 'w', zipfile.ZIP_DEFLATED)
        self.zipdir('ansible/', zipf)
        zipf.close()

    @staticmethod
    def zipdir(path, zipf):
        u""" Put all the contents of a directory into a zipfile """
        for root, _, files in os.walk(path):
            for file in files:
                zipf.write(os.path.join(root, file))

    def deliver_payload(self, bucket_name):
        u""" Put the necessary files into S3 """
        client = self.aws.get_client('s3')
        res = client.upload_file('test-deploy-files.zip', bucket_name, Key='test-delpoy-files.zip')
        from pprint import pprint as pp
        pp(res)
