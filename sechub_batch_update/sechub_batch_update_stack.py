import os, subprocess

from aws_cdk import (
    core,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_sqs as sqs,
    aws_lambda_event_sources,
    aws_kms,
    aws_sam,
)

from sechub_batch_update.sechub_suppression import SecurityHubSuppression


class SechubBatchUpdateStack(core.Stack):
    """
    Creates stack which deploys suppression of Security Hub findings

    account_numbers_parameter: Cloudformation parameter which takes comma separated account number values to which Security Hub suppression applies to
    generator_ids_parameter: Cloudformation parameter which asks for Security Hub generator IDs to suppress

    Stack creates the following resources.

    batch_lambda: Lambda which invokes the Security Hub batch_update_findings
    batch_lambda_role: IAM role which is to be used by Lambda function to suppress SecurityHub findings
    queue: Encrypted queue to batch Security Hub findings that will be suppressed. Target is the batch_lambda for suppression.
    dead_letter_queue: Encrypted SQS dead letter queue to hold unprocessed Security Hub findings which could not be processed by the Lambda
    """

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account_numbers_parameter = core.CfnParameter(
            self,
            "AccountNumbers",
            type="CommaDelimitedList",
            description="AWS Account numbers that the suppression rule applies to",
        )

        generator_ids_parameter = core.CfnParameter(
            self,
            "GeneratorIds",
            type="CommaDelimitedList",
            description="The SecurityHub generator ids to suppress",
            default="aws-foundational-security-best-practices/v/1.0.0/EC2.6",
        )

        account_numbers = account_numbers_parameter.value_as_list
        generator_ids = core.Token.as_list(generator_ids_parameter.value_as_list)

        # avoid circular dependency
        function_name = "security-hub-batch-update-suppression"

        batch_lambda_role = iam.Role(
            self,
            f"{function_name}-role",
            description="Suppression role for Security Hub batch update findings",
            path="/",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )

        batch_lambda = self.create_lambda_function(
            is_inline=False,
            batch_lambda_role=batch_lambda_role,
            function_name=function_name,
        )

        batch_lambda_policy = iam.ManagedPolicy(
            self,
            f"{function_name}-policy",
            description="Suppression policy for Security Hub implementing batch update findings",
            path="/",
            statements=[
                iam.PolicyStatement(
                    sid="CloudWatchLogs",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=[
                        f"arn:aws:logs:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:log-group:/aws/lambda/{function_name}:*"
                    ],
                ),
                iam.PolicyStatement(
                    sid="SecurityHubBatchUpdateFindings",
                    effect=iam.Effect.ALLOW,
                    actions=["securityhub:BatchUpdateFindings"],
                    resources=["*"],
                ),
            ],
        )

        batch_lambda_role.add_managed_policy(batch_lambda_policy)

        queue_encryption_key = aws_kms.Key(
            self,
            "sqs-encryption-key",
            alias="SQSEncryptionKey",
            enable_key_rotation=True,
            pending_window=core.Duration.days(30),
        )
        queue_encryption_key.grant_decrypt(batch_lambda_role)

        dead_letter_queue = sqs.Queue(
            self,
            "securityhub-findings-dead-letter-queue",
            retention_period=core.Duration.days(2),
            visibility_timeout=core.Duration.seconds(130),
            encryption_master_key=queue_encryption_key,
            encryption=sqs.QueueEncryption.KMS,
        )

        queue = sqs.Queue(
            self,
            "securityhub-findings-queue",
            dead_letter_queue=sqs.DeadLetterQueue(
                queue=dead_letter_queue, max_receive_count=1
            ),
            visibility_timeout=core.Duration.seconds(130),
            encryption_master_key=queue_encryption_key,
            encryption=sqs.QueueEncryption.KMS,
        )

        queue.add_to_resource_policy(self.get_enforce_tls_statement(queue.queue_arn))
        dead_letter_queue.add_to_resource_policy(self.get_enforce_tls_statement(dead_letter_queue.queue_arn))

        batch_lambda.add_event_source(
            aws_lambda_event_sources.SqsEventSource(
                queue=queue,
                batch_size=100,
                max_batching_window=core.Duration.seconds(10),
                enabled=True,
            )
        )

        props = {}
        props["account_numbers"] = account_numbers
        props["generator_ids"] = generator_ids
        props["queue"] = queue

        security_suppression = SecurityHubSuppression(
            self, "securityhub-suppression-example", props
        )

    def get_enforce_tls_statement(self, queue_arn):
        enforce_tls_statement = iam.PolicyStatement(
            sid="Enforce TLS for all principals",
            effect=iam.Effect.DENY,
            principals=[
                iam.AnyPrincipal(),
            ],
            actions=[
                "sqs:*",
            ],
            resources=[queue_arn],
            conditions={
                "Bool": {"aws:secureTransport": "false"},
            },
        )
        return enforce_tls_statement

    """
    Performs a local pip install to create a folder of the dependencies.
    CDK will then bundle the layer folder, create assets zip, create hash, and upload to the assets zip to the s3 bucket to create the layer.
    https://github.com/aws-samples/aws-cdk-examples/issues/130
    """
    def create_dependencies_layer(
        self, id: str, requirements_path: str, output_dir: str
    ) -> _lambda.LayerVersion:
        # Install requirements for layer
        if not os.environ.get("SKIP_PIP"):
            subprocess.check_call(
                # Note: Pip will create the output dir if it does not exist
                f"pip install -r {requirements_path} -t {output_dir}/python".split()
            )
        return _lambda.LayerVersion(self, id, code=_lambda.Code.from_asset(output_dir))

    # https://github.com/awslabs/aws-lambda-powertools-python/issues/355#issuecomment-813393424
    # https://serverlessrepo.aws.amazon.com/applications/eu-west-1/057560766410/aws-lambda-powertools-python-layer
    def create_powertools_layer(self: str) -> _lambda.LayerVersion:
        POWER_TOOLS_VER = "1.17.0"
        POWER_TOOLS_ARN = "arn:aws:serverlessrepo:eu-west-1:057560766410:applications/aws-lambda-powertools-python-layer"
        POWERTOOLS_BASE_NAME = "AWSLambdaPowertools"

        powertools_application = aws_sam.CfnApplication(
            self,
            f"{POWERTOOLS_BASE_NAME}Application",
            location={
                "applicationId": POWER_TOOLS_ARN,
                "semanticVersion": POWER_TOOLS_VER,
            },
        )

        return _lambda.LayerVersion.from_layer_version_arn(
            self,
            f"{POWERTOOLS_BASE_NAME}",
            powertools_application.get_att("Outputs.LayerVersionArn").to_string(),
        )

    def create_lambda_function(self, is_inline, batch_lambda_role, function_name):
        if is_inline:
            lambda_layer = self.create_powertools_layer()
            with open(f"./lambda/batch_update.py", encoding="utf8") as fp:
                handler_code = fp.read()
                lambda_code = _lambda.InlineCode(handler_code)
                lambda_handler = "index.handler"
        else:
            lambda_layer = self.create_dependencies_layer(
                id="lambdalayer",
                requirements_path="./lambda/requirements.txt",
                output_dir="./lambda_layer",
            )
            lambda_code = _lambda.Code.asset("lambda")
            lambda_handler = "batch_update.handler"

        return _lambda.Function(
            self,
            "batchupdate",
            runtime=_lambda.Runtime.PYTHON_3_8,
            code=lambda_code,
            layers=[lambda_layer],
            handler=lambda_handler,
            role=batch_lambda_role,
            function_name=function_name,
            description="Suppression lambda for Security Hub implements batch update findings",
            retry_attempts=2,
            timeout=core.Duration.minutes(2),
        )
