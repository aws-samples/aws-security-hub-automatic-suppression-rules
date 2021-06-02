# How to Create Auto-Suppression Rules in AWS Security Hub

This project is for SecurityHub auto supression of findings using the `batch_update_findings` API call.

## Deploy

The following commands shows how to deploy the solution by using the AWS Cloud Development Kit (AWS CDK) (https://aws.amazon.com/cdk/). 

First, the CDK will initialize your environment and upload the Lambda assets to S3. 

```
cdk bootstrap
```

Then, you can deploy the solution to your account. 

Specify the generator id or comma separated list of generator ids the suppression rule should apply to.

Specify the account number or comma separated list of account numbers the suppression rule should apply to.

```
cdk deploy sechub-finding-suppression --parameters GeneratorIds=aws-foundational-security-best-practices/v/1.0.0/EC2.6 --parameters AccountNumbers=123456789123
```


## Testing

Create a VPC that does not have flow logs enabled.  We have included a test VPC that you can deploy.

```
cdk deploy vpc-test-suppression
```            


Verify that the Security Hub finding EC2.6 has been suppressed in the parent account and the target account.  

You might need to wait a few minutes for the AWS Config recorder to detect the newly created resource. Then to manually trigger the periodic Config rule securityhub-vpc-flow-logs-enabled-ID-HERE.



After verifying the suppression, delete the test VPC you created to test the suppression rule.
```
cdk destroy vpc-test-suppression
```

## Creating pydocs

```
python3 -m pydoc -w sechub_batch_update/sechub_batch_update_stack.py sechub_batch_update/sechub_suppression.py lambda/batch_update.py sechub_batch_update/vpc_test.py 

mv *.html pydocs/
```
