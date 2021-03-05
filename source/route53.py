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

class Route53:

    def __init__(self):
        with open("config.json") as f:
            self.conf = json.load(f)
        
        self.role     = self.conf['role']
        self.accounts = self.conf['accounts']
        self.regions  = self.conf['regions']
        self.names    = self.conf["names"]

        self.data     = {}
        self.cn_redis = redis.Redis(host='redis', port=6379, db=0)

    def getzonerecords(self,client,zoneid):
        blacklist = ["TXT","MX","NS","SOA","SRV"]
        paginator = client.get_paginator('list_resource_record_sets')
        try:
            source_zone_records = paginator.paginate(HostedZoneId=zoneid)
            for record_set in source_zone_records:
                for record in record_set['ResourceRecordSets']:
                    if record["Type"] not in blacklist and "_" not in record["Name"]:
                        self.data[record["Name"]] = record
        except Exception as error:
            log.error('An error occurred getting source zone records:')
            log.error(str(error))
            raise
    
    def aggregaterecords(self,client):
        zoneids = {}
        zones = client.list_hosted_zones()
        for zone in zones["HostedZones"]:
            if zone["Name"] in self.names:
                zoneids[zone["Name"]] = zone["Id"]

        for name in zoneids:
            self.getzonerecords(client,zoneids[name])

    def call_sts(self,data,account):
        # assume the role for the account.
        tokens = assume_role(account,self.role)
        # enumerate regions.
        if tokens != None:
            for region in self.regions:
                log.info("[*] Scanning Region: " + region)
                self.aggregaterecords(client_tech('route53',region,tokens))
            
    def run(self):
        for account in self.accounts:
            log.info("[*] Gathering Route53 data for AccountID: " + account)
            self.call_sts(self.data,account)
        # After running all jobs, add the data to redis.
        log.info("[*] Finished Route53 Aggregation.")
        log.info("[*] Sending Data to Redis.")
        self.cn_redis.set("r53records", encrypt(self.data))
        