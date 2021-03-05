import redis,pickle, json, requests,logging, json_logging, sys

from crypt import encrypt, decrypt

# log is initialized without a web framework name
json_logging.ENABLE_JSON_LOGGING = True
json_logging.init_non_web()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler(sys.stdout))

class S3Alerts:

    def __init__(self):
        # Initialize the whitelist.
        with open("s3_whitelist.json") as f:
            self.whitelist = json.load(f)['Buckets']

        # Get the routing key from config file.
        with open("config.json") as f:
            self.ROUTING_KEY = json.load(f)['routingkey']

        self.cn_redis = redis.Redis(host='redis', port=6379, db=0)
        # keep track of Pager State.
        try:
            self.reported = decrypt(self.cn_redis.get('reported'))
        except:
            self.cn_redis.set('reported',encrypt([]))
            self.reported = decrypt(self.cn_redis.get('reported'))
        # Load Cannonical and S3 Data.
        self.cannonicals = decrypt(self.cn_redis.get('cannonicals'))
        self.s3_data = decrypt(self.cn_redis.get('s3auditor'))


    def secops_pager(self,summary):

        header = {
            "Content-Type": "application/json"
        }

        payload = {
            "routing_key": self.ROUTING_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "source": "AWS SecOps Auditor System.",
                "severity": "critical"
            }
        }

        response = requests.post('https://events.pagerduty.com/v2/enqueue',
                                data=json.dumps(payload),
                                headers=header)

        if response.json()["status"] == "success":
            log.info('[*] PagerDuty Incident Created')
        else:
            log.info("[*]Error Creating PagerDuty Event: " + response.text)

    def run(self):

        # Load the whitelist
        def map_perms(dat,bucket):
            try:
                return {bucket:(dat['Grantee']['ID'],dat['Grantee']['Type'],dat['Permission'])}
            except KeyError:
                '''Ignore this Error'''
                #print("[*] Got KeyError LogDeliveryGroup?: " + bucket + " " + str(dat))

        # Example evil cannonical ID.
        # d3d8d9782341148dcf75d3dcbb1c7cda2e485256abe59f7933e72f995be2159b
        # ^ This is my personal account =)

        # Looks for non-recognized cannonicals.
        def find_issues(item):
            for key in item:
                if item[key][0] not in self.cannonicals and item[key][0] not in self.reported:
                    log.info("[*] Security Alert!")
                    log.info("[*] Detected UnAuthorized Access: " + str(item[key]))

                    # Send PagerDuty Alert for Violation.
                    text = """[SEC] UnKnown Cannonical Discovered on S3 Bucket "{}".\n[SEC] S3 Bucket ACL: {}""".format(key,item)
                    self.secops_pager(text)
                    self.reported.append(item[key][0])

        log.info("[*] Checking if Alerts need to be generated for non-whitelisted buckets.")
        for bucket in self.s3_data:
            dat = [map_perms(dic,bucket) for dic in self.s3_data[bucket]['permissions']]
            #Public Alert gets triggered here.
            if self.s3_data[bucket]['IsPublic'] == True:
                if bucket not in self.whitelist and bucket not in self.reported:
                    log.info("[*] Security Alert!")
                    log.info("[*] Detected Open Internet Access for s3 bucket: " + str(bucket))

                    # Send PagerDuty Alert for Violation.
                    text = """[SEC] Internet Access Discovered on S3 Bucket "{}" which is not whitelisted.""".format(bucket)
                    self.secops_pager(text)
                    self.reported.append(bucket)
        log.info("[*] Done Checking.")
