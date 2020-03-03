from ipauditor import IPAuditor
from s3auditor import S3Auditor
from s3alerts import S3Alerts
import arrow, glog

import redis, pickle, time
from datetime import datetime

def main():

    while True:

        # Run the ipscanner.
        ipauditor = IPAuditor()
        ipauditor.run()

        # Run the S3 Auditor.
        s3auditor = S3Auditor()
        s3auditor.run()

        # Run against s3 metadata to check for issues.
        s3alert = S3Alerts()
        s3alert.run()

        # Sleep the system for 60 minutes.
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        glog.info("[*] Run Completed at - " + current_time + ". Sleeping for 60 Minutes.")
        time.sleep(3600)

if __name__ == "__main__":
    main()
