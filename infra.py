u""" Manage infrastructure resources """
import sys
from troposphere import autoscaling, Base64, cloudformation, Join, Parameter, \
    Ref, Tags, Template
from troposphere.autoscaling import AutoScalingGroup, LaunchConfiguration, Tag
from troposphere.ec2 import InternetGateway, NetworkAcl, NetworkAclEntry, \
    PortRange, Route, RouteTable, SecurityGroup, SecurityGroupRule, \
    Subnet, SubnetNetworkAclAssociation, SubnetRouteTableAssociation, VPC, \
    VPCGatewayAttachment
import troposphere.ec2 as ec2
from botocore.exceptions import ClientError
from aws import AWS


class InfrastructureTemplate():
    u""" AWS Cloudformation Infrastructure Template """

    def __init__(self):
        u""" Infrastructure Class Contructor """
        self.aws = AWS()
        self.ref_stack_id = Ref('AWS::StackId')
        self.keypair_name = 'test-deploy-keypair'

        # NOTE: Troposphere doesn't have a template feature to make KeyPairs
        #       So handle this ad-hoc for now.
        if self.keypair_doesnt_exist():
            self.create_keypair()

        self.template = Template()
        self.template.add_version('2010-09-09')
        self.template.add_description(
            'AWS Cloudformation Template for autoscaled, load balance controlled EC2 service')
        self.template.add_parameter(Parameter('KeyName',
                                              Description='Name of an existing EC2 KeyPair',
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
        self.vpc = self.template.add_resource(VPC('TestDeployVpc',
                                                  CidrBlock='10.0.0.0/16',
                                                  Tags=Tags(Application=self.ref_stack_id)))
        self.subnet = self.template.add_resource(Subnet('TestDeploySubnet',
                                                        VpcId=Ref(self.vpc),
                                                        CidrBlock='10.0.0.0/24',
                                                        Tags=Tags(Application=self.ref_stack_id)))
        self.gateway = self.template.add_resource(InternetGateway('TestDeployGateway',
                                                                  Tags=Tags(Application=self.ref_stack_id)))
        self.gatewayattach = self.template.add_resource(VPCGatewayAttachment('AttachGateway',
                                                                             VpcId=Ref(self.vpc),
                                                                             InternetGatewayId=Ref(self.gateway)))
        self.route_table = self.template.add_resource(RouteTable('RouteTable',
                                                                 VpcId=Ref(self.vpc),
                                                                 Tags=Tags(Application=self.ref_stack_id)))
        self.route = self.template.add_resource(Route('Route',
                                                      DependsOn='AttachGateway',
                                                      GatewayId=Ref('TestDeployGateway'),
                                                      DestinationCidrBlock='0.0.0.0/0',
                                                      RouteTableId=Ref(self.route_table)))
        self.subnet_route_association = self.template.add_resource(
            SubnetRouteTableAssociation('SubnetRouteTableAssociation',
                                        SubnetId=Ref(self.subnet),
                                        RouteTableId=Ref(self.route_table)))

        self.network_acl = self.template.add_resource(NetworkAcl('NetworkAcl',
                                                                 VpcId=Ref(self.vpc),
                                                                 Tags=Tags(Application=self.ref_stack_id)))
        self.inbound_private_http = self.template.add_resource(NetworkAclEntry('InboundHTTP',
                                                                               NetworkAclId=Ref(self.network_acl),
                                                                               RuleNumber='100',
                                                                               Protocol='6',
                                                                               PortRange=PortRange(To='80',
                                                                                                   From='80'),
                                                                               Egress='false',
                                                                               RuleAction='allow',
                                                                               CidrBlock='0.0.0.0/0'))
        self.inbound_private_https = self.template.add_resource(NetworkAclEntry('InboundHTTPS',
                                                                                NetworkAclId=Ref(self.network_acl),
                                                                                RuleNumber='101',
                                                                                Protocol='6',
                                                                                PortRange=PortRange(To='443',
                                                                                                    From='443'),
                                                                                Egress='false',
                                                                                RuleAction='allow',
                                                                                CidrBlock='0.0.0.0/0'))
        self.inbound_ssh = self.template.add_resource(NetworkAclEntry('InboundSSH',
                                                                      NetworkAclId=Ref(self.network_acl),
                                                                      RuleNumber='102',
                                                                      Protocol='6',
                                                                      PortRange=PortRange(To='22',
                                                                                          From='22'),
                                                                      Egress='false',
                                                                      RuleAction='allow',
                                                                      CidrBlock='0.0.0.0/0'))
        self.inbound_response = self.template.add_resource(NetworkAclEntry('InboundResponsePorts',
                                                                           NetworkAclId=Ref(self.network_acl),
                                                                           RuleNumber='103',
                                                                           Protocol='6',
                                                                           PortRange=PortRange(To='65535',
                                                                                               From='1024'),
                                                                           Egress='false',
                                                                           RuleAction='allow',
                                                                           CidrBlock='0.0.0.0/0'))
        self.outbound_http = self.template.add_resource(NetworkAclEntry('OutboundHTTP',
                                                                        NetworkAclId=Ref(self.network_acl),
                                                                        RuleNumber='100',
                                                                        Protocol='6',
                                                                        PortRange=PortRange(To='80',
                                                                                            From='80'),
                                                                        Egress='true',
                                                                        RuleAction='allow',
                                                                        CidrBlock='0.0.0.0/0'))
        self.outbound_https = self.template.add_resource(NetworkAclEntry('OutboundHTTPS',
                                                                         NetworkAclId=Ref(self.network_acl),
                                                                         RuleNumber='101',
                                                                         Protocol='6',
                                                                         PortRange=PortRange(To='443',
                                                                                             From='443'),
                                                                         Egress='true',
                                                                         RuleAction='allow',
                                                                         CidrBlock='0.0.0.0/0'))
        self.outbound_response = self.template.add_resource(NetworkAclEntry('OutboundResponsePorts',
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
                                        NetworkAclId=('NetworkAcl')))
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
                                Metadata=autoscaling.Metadata(
                                    cloudformation.Init({
                                        "config": cloudformation.InitConfig(
                                            services={
                                                "sysvinit": cloudformation.InitServices({
                                                    "rsyslog": cloudformation.InitService(
                                                        enabled=True,
                                                        ensureRunning=True,
                                                        files=['/etc/rsyslog.d/20-somethin.conf']
                                                    )
                                                })
                                            }
                                        )
                                    }),
                                    cloudformation.Authentication({
                                        "DeployUserAuth": cloudformation.AuthenticationBlock(
                                            type="S3",
                                            accessKeyId='DeployUserAccessKey',
                                            secretKey='DeployUserSecretKey'
                                        )
                                    })
                                ),
                                UserData=Base64(Join('', [
                                    "#!/bin/bash\n",
                                    "cfn-signal -e 0",
                                    "    --resource AutoscalingGroup",
                                    "    --stack ", Ref("AWS::StackName"),
                                    "    --region ", Ref("AWS::Region"), "\n"
                                ])),
                                ImageId='AmiId',
                                KeyName='KeyName',
                                BlockDeviceMappings=[
                                    ec2.BlockDeviceMapping(
                                        DeviceName="/dev/sda1",
                                        Ebs=ec2.EBSBlockDevice(
                                            VolumeSize="8"
                                        )
                                    ),
                                ],
                                SecurityGroups=[Ref(SecurityGroup)],
                                InstanceType="m1.small"))

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
    def create_keypair(self):
        u""" Create a keypair resource """
        client = self.aws.get_client('ec2')
        try:
            res = client.create_key_pair(KeyName=self.keypair_name)
            print(res['KeyMaterial'])
        except ClientError as ex:
            sys.exit(ex)

    def print_template(self, output='yaml'):
        u""" Dump Cloudformation Template """
        if 'yaml' not in output:
            print(self.template.to_json())
        else:
            print(self.template.to_yaml())
