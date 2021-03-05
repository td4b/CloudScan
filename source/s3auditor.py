import boto3, pickle, redis, json, logging, json_logging, sys
from botocore.exceptions import ClientError
from session import assume_role, s3_session

from crypt import encrypt, decrypt

# log is initialized without a web framework name
json_logging.ENABLE_JSON_LOGGING = True
json_logging.init_non_web()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler(sys.stdout))

class S3Auditor:

    def __init__(self):
        with open("config.json") as f:
            self.conf = json.load(f)
        self.role     = self.conf['role']
        self.accounts = self.conf['accounts']
        self.cn_redis = redis.Redis(host='redis', port=6379, db=0)
        self.data     = {}
        # Whitelist trusted cannonicals.
        # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html
        self.cannonicals = ['c4c1ede66af53448b93c283ce9448c4ba468c9432aa01d700d3878632f77d2d0']
        self.buckets  = []

    def map_cannonicals(self,dic,client,name,account):
        # Adds S3 items into our struct for redis.
        def add_item(result,check_pub):
            for item in result:
                dic[name] = {
                    'ID':result['Owner']['ID'],
                    'permissions':result['Grants'],
                    'IsPublic':check_pub,
                    'technology':'s3',
                    'account':account
                }
        try:
            result = client.get_bucket_acl(Bucket=name)
            log.info("[*] Got bucket ACL for Bucket: " + name)
            if result['Owner']['ID'] not in self.cannonicals:
                self.cannonicals.append(result['Owner']['ID'])
            # Also check on the ACL if the bucket is Public.
            uri = [uri for uri in [policy['URI'] for policy in [item['Grantee'] for item in result['Grants']] if policy['Type'] == 'Group'] if uri == 'http://acs.amazonaws.com/groups/global/AllUsers']
            if len(uri) >= 1:
                log.info("[*] Public Bucket ACL found for Bucket: " + name)
                return add_item(result,True)
            try:
                # Checks Public Policy if
                check_pub = client.get_bucket_policy_status(Bucket=name)['PolicyStatus']['IsPublic']
                log.info("[*] Got bucket Policy for Bucket: " + name)
                # Populate Cannonical IDs.
                return add_item(result,check_pub)
            except Exception as e:
                log.info("Unexpected error: %s" % e + " Cannot get Bucket Policy: " + name + " Marking Public as False.")
                return add_item(result,False)
        except Exception as e:
            log.info("Unexpected error: %s" % e + " Cannot get Bucket ACL: " + name)

    def s3_inspect(self,dic,client,account):
        bucket_list = client.list_buckets()
        for ele in bucket_list['Buckets']:
            self.map_cannonicals(self.data,client,ele['Name'],account)
            if ele['Name'] not in self.buckets:
                self.buckets.append(ele['Name'])

    def call_sts(self,data,account):
        # assume the role for the account.
        tokens = assume_role(account,self.role)
        if tokens != None:
            self.s3_inspect(self.data,s3_session(tokens),account)

    def run(self):
        for account in self.accounts:
            log.info("[*] Checking Buckets in account: " + account)
            self.call_sts(self.data,account)

        log.info("[*] Completed Collecting S3 Data.")
        log.info("[*] Sending S3 Data to Redis.")

        # Dump s3 Metadata into Redis.
        self.cn_redis.set("s3auditor", encrypt(self.data))

        # Dump the cannonical IDs into redis.
        self.cn_redis.set("cannonicals", encrypt(self.cannonicals))
