import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

import json, boto3
import botocore.exceptions as boto3exceptions

from aws_lambda_powertools.utilities.batch import PartialSQSProcessor

sh_client = boto3.client("securityhub")

"""
Used by the lambda to tracks all of the Security Hub finding ids that will be suppressed.
Each Lambda invocation will create a separate instance of this class.
"""
class RecordsHandler:
    def __init__(self):
        self.finding_identifiers = []

    def record_handler(self, record):
        payload = json.loads(record["body"])
        logger.info(f"payload {payload}")
        finding_identifier = {
            "Id": payload["detail"]["findings"][0]["Id"],
            "ProductArn": payload["detail"]["findings"][0]["ProductArn"],
        }
        self.finding_identifiers.append(finding_identifier)

    def get_finding_identifiers(self):
        return self.finding_identifiers

"""
Uses the Lambda Powertools PartialSQSProcessor in order to build the findings id list.
Lambda powertools is used to prevent successfully processed messages being returned to SQS
https://awslabs.github.io/aws-lambda-powertools-python/latest/utilities/batch/
"""
def handler(event, context):
    records = event["Records"]
    logger.info(f"records {records}")

    processor = PartialSQSProcessor()

    rh = RecordsHandler()
    with processor(records, rh.record_handler) as proc:
        proc.process()

    finding_identifiers = rh.get_finding_identifiers()
    logger.info(f"finding_identifiers {finding_identifiers}")

    try:
        response = sh_client.batch_update_findings(
            FindingIdentifiers=finding_identifiers,
            Severity={"Label": "INFORMATIONAL"},
            Workflow={"Status": "SUPPRESSED"},
        )
        for processed_findings in response["ProcessedFindings"]:
            logger.info(
                f"processed and suppressed id {processed_findings['Id']} productarn {processed_findings['ProductArn']}"
            )

        for unprocessed_findings in response["UnprocessedFindings"]:
            logger.error(
                f"unprocessed finding id {unprocessed_findings['FindingIdentifier']['Id']} productarn {unprocessed_findings['FindingIdentifier']['ProductArn']} error code {unprocessed_findings['ErrorCode']} error message {unprocessed_findings['ErrorMessage']}"
            )

    except boto3exceptions.ClientError as error:
        logger.exception("client error")
        raise ConnectionError(f"Client error invoking batch update findings {error}")
    except boto3exceptions.ParamValidationError as error:
        logger.exception("invalid parameters")
        raise ValueError(f"The parameters you provided are incorrect: {error}")

    return {"statusCode": 200}
