from aws_cdk import (
    core,
    aws_events as events,
    aws_events_targets as event_targets,
)


class SecurityHubSuppression(core.Construct):
    """
    CDK Construct which creates the CloudWatch events pattern

    props['generator_ids']: Security Hub generator IDs to suppress
    props['queue']: Queue to batch findings and is that target of the Security Hub suppression event
    """

    def __init__(
        self, scope: core.Construct, construct_id: str, props, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        generator_ids = props["generator_ids"]
        queue = props["queue"]
        event_pattern_obj = events.EventPattern(
            source=["aws.securityhub"],
            detail_type=["Security Hub Findings - Imported"],
            detail={
                "findings": {
                    "GeneratorId": generator_ids,
                    "AwsAccountId": props["account_numbers"],
                    "Workflow": {"Status": ["NEW"]},
                },
            },
        )

        self.event_rule = events.Rule(
            self,
            "securityhub-suppression-rule",
            description=f"SecurityHub Suppression rule",
            event_pattern=event_pattern_obj,
        )

        self.event_rule.add_target(event_targets.SqsQueue(queue))
