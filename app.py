#!/usr/bin/env python3

from aws_cdk import core

from sechub_batch_update.sechub_batch_update_stack import SechubBatchUpdateStack
from sechub_batch_update.vpc_test import VPCTest

app = core.App()
SechubBatchUpdateStack(
    app,
    "sechub-finding-suppression",
    synthesizer=core.DefaultStackSynthesizer(
        generate_bootstrap_version_rule=False,
    ),
)
VPCTest(app, "vpc-test-suppression")

app.synth()
