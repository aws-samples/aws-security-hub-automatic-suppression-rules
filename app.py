#!/usr/bin/env python3

from aws_cdk import core

from sechub_batch_update.sechub_batch_update_stack import SechubBatchUpdateStack
from sechub_batch_update.vpc_test import VPCTest

app = core.App()
# generate_bootstrap_version_rule should be set to False when doing inline with cfn template and not using cdk.
# otherwise generate_bootstrap_version_rule should be True when using CDK to deploy
SechubBatchUpdateStack(
    app,
    "sechub-finding-suppression",
    synthesizer=core.DefaultStackSynthesizer(
        generate_bootstrap_version_rule=True,
    ),
)
VPCTest(app, "vpc-test-suppression-1")

app.synth()
