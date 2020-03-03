
<div align="center">
<img src="https://github.com/collectivehealth/CloudScan/blob/master/icon.png" width="40%">
</div>

## Description

Cloudscan is an Open Source Project developed to help automate Security Events and Alerts. In it's current state, the tool aims to alert on S3 buckets that have been publically exposed.

This however, is not the only functionality of Cloudscan, the tool is designed to audit the entire 'Cloud Attack Surface.' So it not only looks at Open S3 buckets... but also Open EC2 instances, Application Load-Balancers as well as RDS Instances.

The public resources can be queried through the protected API port on the container. These IP addresses can be put into a vulnerability scanner or linked to one via the API to enable continuous security monitoring.

## Tool PreReqs, Installation & Setup

This tool is designed to run on a kubernetes cluster but it can also be configured to run on a server running docker or docker-compose. However, that configuration is outside the scope of this release.

That being said the deployment image can be built using the supplied 'Dockerfile'.

In the manifest.yaml file you will see the config and whitelist files the tools use for the assume role and s3 auditing functionality.

The tool is required to be able to assume roles in the accounts you set up with the attached policy document (note the permissions... such as describe ec2, elb, rds ect.) See 'policydoc.json'

## Terraform

Provided is a terraform template to help get you going in terms of the IAM provisioning of the tool. Please note that this should be used as a template to guide you to the finished IAM implementation. This can be found under the 'terraform' folder.
