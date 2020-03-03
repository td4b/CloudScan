import boto3, socket, redis, pickle, sys, json, glog
from session import client_tech, assume_role
from botocore.exceptions import ClientError

class IPAuditor:

    def __init__(self):
        with open("config.json") as f:
            self.conf = json.load(f)

        self.role     = self.conf['role']
        self.accounts = self.conf['accounts']
        self.regions  = self.conf['regions']
        self.data     = {}
        self.cn_redis = redis.Redis(host='redis', port=6379, db=0)

    # Populate Instance IP Addresses in our Object data struct.
    def ec2_gather(self,dic,client,account,region):
        try:
            paginator = client.get_paginator('describe_instances')
            page_iterator = paginator.paginate()
        except ClientError as e:
            glog.error('Got Error: ' + str(e))
        for page in page_iterator:
            instances = page['Reservations']
            result = [x['Instances'][0] for x in instances if 'PublicIpAddress' in x['Instances'][0]]
            for item in result:
                dic[item['InstanceId']] = {
                    'ip':item['PublicIpAddress'],
                    'technology':'ec2',
                    'account':account,
                    'region': region
                }

    def classicELB(self,dic,client,account,region):
        try:
            paginator = client.get_paginator('describe_load_balancers')
            page_iterator = paginator.paginate()
        except ClientError as e:
            glog.error('Got Error: ' + str(e))
        for elbs in page_iterator:
            for key in elbs['LoadBalancerDescriptions']:
                try:
                    ipaddr = socket.gethostbyname(key['DNSName'])
                except Exception:
                    ipaddr = None
                dic[key['DNSName']] = {
                    'ip':ipaddr,
                    'technology':'classic-elb',
                    'account':account,
                    'region':region
                }

    def appELB(self,dic,client,account,region):
        try:
            paginator = client.get_paginator('describe_load_balancers')
            page_iterator = paginator.paginate()
        except ClientError as e:
            glog.error('Got Error: ' + str(e))
        for elbs in page_iterator:
            for key in elbs['LoadBalancers']:
                try:
                    ipaddr = socket.gethostbyname(key['DNSName'])
                except Exception:
                    ipaddr = None
                dic[key['DNSName']] = {
                    'ip':ipaddr,
                    'technology':'application-elb',
                    'account':account,
                    'region':region
                }

    def rds_gather(self,dic,client,account,region):
        try:
            paginator = client.get_paginator('describe_db_instances')
            page_iterator = paginator.paginate()
        except ClientError as e:
            glog.error('Got Error: ' + str(e))
        for rds in page_iterator:
            for key in rds['DBInstances']:
                if key['PubliclyAccessible'] == True:
                    try:
                        ipaddr = socket.gethostbyname(key['Endpoint']['Address'])
                    except Exception:
                        ipaddr = None
                    dic[key['Endpoint']['Address']] = {
                        'ip':ipaddr,
                        'technology':'rds',
                        'account':account,
                        'region':region
                    }

    # multiple gathers' needed to be called here.
    def elb_gather(self,account,region,tokens):
        self.classicELB(self.data,client_tech('elb',region,tokens),account,region)
        self.appELB(self.data,client_tech('elbv2',region,tokens),account,region)

    def call_sts(self,data,account):
        # assume the role for the account.
        tokens = assume_role(account,self.role)
        # enumerate regions.
        if tokens != None:
            for region in self.regions:
                glog.info("[*] Scanning Region: " + region)
                self.elb_gather(account,region,tokens)
                self.ec2_gather(self.data,client_tech('ec2',region,tokens),account,region)
                self.rds_gather(self.data,client_tech('rds',region,tokens),account,region)

    def run(self):
        for account in self.accounts:
            glog.info("[*] Gathering ip data for AccountID: " + account)
            self.call_sts(self.data,account)
        # After running all jobs, add the data to redis.
        glog.info("[*] Finished IPScans.")
        glog.info("[*] Sending Data to Redis.")
        dumped = pickle.dumps(self.data)
        self.cn_redis.set("ipauditor", dumped)
