#!/usr/bin/env python3

from aws_cdk import core

from sechub_batch_update.sechub_batch_update_stack import SechubBatchUpdateStack
from sechub_batch_update.vpc_test import VPCTest

app = core.App()
SechubBatchUpdateStack(app, "sechub-finding-suppression")
VPCTest(app, "vpc-test-suppression")

app.synth()
