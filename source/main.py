from ipauditor import IPAuditor
from s3auditor import S3Auditor
from s3alerts import S3Alerts
from route53 import Route53
import ray, time, arrow, logging, json_logging, sys

# initialize the ray system (for process parallism)
ray.init()

# log is initialized without a web framework name
json_logging.ENABLE_JSON_LOGGING = True
json_logging.init_non_web()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler(sys.stdout))

from datetime import datetime

@ray.remote
def R53runner():
    r53run = Route53()
    r53run.run()

@ray.remote 
def IPRunner():
    iprun = IPAuditor()
    iprun.run()

@ray.remote
def S3Runner():
    # Run s3 Auditor before alerting system.
    s3run = S3Auditor()
    s3run.run()
    # Run s3 alerter after running audits.
    s3alertrun = S3Alerts()
    s3alertrun.run()

def main():
    # Run these tests continuously (every hour).
    while True:

        # Run the audit jobs in parallel.
        ray.get([R53runner.remote(),IPRunner.remote(),S3Runner.remote()])
   
        # Sleep the system for 60 minutes.
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        log.info("[*] Run Completed at - " + current_time + ". Sleeping for 60 Minutes.")
        time.sleep(3600)

if __name__ == "__main__":
    main()
