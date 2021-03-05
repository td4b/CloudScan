import boto3, socket, redis, pickle, sys, json, logging, json_logging
from session import client_tech, assume_role
from botocore.exceptions import ClientError

from crypt import encrypt, decrypt

# log is initialized without a web framework name
json_logging.ENABLE_JSON_LOGGING = True
json_logging.init_non_web()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler(sys.stdout))

class IPAuditor:

    def __init__(self):
        with open("config.json") as f:
            self.conf = json.load(f)

        self.role     = self.conf['role']
        self.accounts = self.conf['accounts']
        self.regions  = self.conf['regions']
        self.data     = {}
        self.cn_redis = redis.Redis(host='redis', port=6379, db=0)

    def sg_gather(self,dic,client,account,region):
        try:
            paginator = client.get_paginator('describe_security_groups')
            page_iterator = paginator.paginate()
        except ClientError as e:
            log.error('Got Error: ' + str(e))
        for page in page_iterator:
            group = page['SecurityGroups']
            permissions = [{'Name':sg['GroupId'],'Description':sg['Description'],'ACL':sg['IpPermissions']} for sg in group]
            for sg in permissions:
                rules = []
                if sg['ACL'] != [] and sg['ACL'][0]['IpRanges'] != []:
                    for ip in sg['ACL'][0]['IpRanges']:
                        if ip['CidrIp'] == "0.0.0.0/0":
                            dic[sg['Name']] = {
                                'Acl':sg['ACL'],
                                'technology':'SecurityGroup',
                                'Description':sg['Description'],
                                'account':account,
                                'region': region
                            }

    def sg_report(self, dic):
        sgscope = []
        for key in dic:
            if dic[key]['technology'] ==  'SecurityGroup':
                sgscope.append({key:dic[key]})
        log.info('[*] Security Group Report written to filesystem <ruleset.html> <sglist.csv>')
        document = '''
        <!DOCTYPE html>
        <html>
        <body>
        <h1>AWS Firewall Configuration Review</h1>
        <p>Compliance</p>
        <pre id="json"></pre>
        <script>
        var jsonVar = {}
        document.getElementById("json").textContent = JSON.stringify(jsonVar, undefined, 2);
        </script>
        </body>
        </html>
        '''.format(str(sgscope))

        # Create HTML formatting of Rules to be reviewed.
        with open("ruleset.html","w") as f:
            f.write(document)

        # create CSVof security Group and owner assignments as well as Description.
        with open("sglist.csv","w") as f:
            f.write('securitygroup,region,owner,description,reason\n')
            for dic in sgscope:
                for key in dic:
                    f.write(key + "," + dic[key]['account'] + "," + dic[key]['region'] + "," + dic[key]['Description'] + ",N/A,Reason\n")

    # Populate Instance IP Addresses in our Object data struct.
    def ec2_gather(self,dic,client,account,region):
        try:
            paginator = client.get_paginator('describe_instances')
            page_iterator = paginator.paginate()
        except ClientError as e:
            log.error('Got Error: ' + str(e))
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
            log.error('Got Error: ' + str(e))
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
            log.error('Got Error: ' + str(e))
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
            log.error('Got Error: ' + str(e))
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
                log.info("[*] Scanning Region: " + region)
                self.sg_gather(self.data,client_tech('ec2',region,tokens),account,region)
                self.elb_gather(account,region,tokens)
                self.ec2_gather(self.data,client_tech('ec2',region,tokens),account,region)
                self.rds_gather(self.data,client_tech('rds',region,tokens),account,region)
            self.sg_report(self.data)

    def run(self):
        for account in self.accounts:
            log.info("[*] Gathering ip data for AccountID: " + account)
            self.call_sts(self.data,account)
        # After running all jobs, add the data to redis.
        log.info("[*] Finished IPScans.")
        log.info("[*] Sending Data to Redis.")
        self.cn_redis.set("ipauditor", encrypt(self.data))
