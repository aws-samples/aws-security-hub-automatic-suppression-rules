from aws_cdk import (
    aws_ec2 as ec2,
    core,
)

class VPCTest(core.Stack):
    """
    THIS STACK IS FOR TESTING PURPOSES ONLY. DELETE THIS STACK AFTER YOU HAVE COMPLETED YORU TESTING.

    This creates a VPC without vpc flow logs enabled.
    """
    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(
            self,
            "VPC-test",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="isolated-subnet", subnet_type=ec2.SubnetType.ISOLATED
                ),
            ],
        )
