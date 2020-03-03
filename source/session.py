import boto3, glog
from botocore.exceptions import ClientError

def client_tech(tech,region,tokens):
    client = boto3.client(tech,
            region_name=region,
            aws_access_key_id=tokens[0],
            aws_secret_access_key=tokens[1],
            aws_session_token=tokens[2]
            )
    return client

def s3_session(tokens):
    client = boto3.client('s3',
            aws_access_key_id=tokens[0],
            aws_secret_access_key=tokens[1],
            aws_session_token=tokens[2]
            )
    return client

def iam_session(tokens):
        client = boto3.client('iam',
                aws_access_key_id=tokens[0],
                aws_secret_access_key=tokens[1],
                aws_session_token=tokens[2]
                )
        return client

def assume_role(account,role):
    boto_sts = boto3.client('sts')
    arn ='arn:aws:iam::' + account + ':role/' + role
    try:
        sts_response = boto_sts.assume_role(RoleArn=arn, RoleSessionName='securitymonkey')
        newsession_id = sts_response["Credentials"]["AccessKeyId"]
        newsession_key = sts_response["Credentials"]["SecretAccessKey"]
        newsession_token = sts_response["Credentials"]["SessionToken"]
        glog.info("[*] Assumed Role: " + arn)
        return newsession_id,newsession_key,newsession_token
    except ClientError as e:
        glog.error("Account= " + account + " Could not be assumed by Tool! Error: " + str(e))
        return None
