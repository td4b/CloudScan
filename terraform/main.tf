
## Account Specific Config
## This config is only aplied to the EC2 instance running cloudscan.
## Notice that the policy sets the trust relationship for cross account access.
## These would need to be modified to reflect your accountID.

# Instance Role that allows the Assume Role to happen.
# Attached directly to EC2 instance as an Instance profile.
resource "aws_iam_role" "CloudScanIntanceRole" {
  name = "CloudScanIntanceRole"

  assume_role_policy = <<EOF
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": "sts:AssumeRole",
              "Resource": [
                  "arn:aws:iam::11111111:role/CloudScanRole",
                  "arn:aws:iam::22222222:role/CloudScanRole"
              ]
          }
      ]
  }
EOF
}

## Deploy to all Accounts.
## This config is applied to all Accounts so that the role is provisioned in each account.
## Note the trust relationsip here is set back to the InstanceProfile set above.

## Please note: Even after the creation of these you will

# Role defined in the Account that provides cloudscan permissions to audit.
resource "aws_iam_role" "CloudScanRole" {
  name = "CloudScanRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    },
    {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": [
            "arn:aws:iam::11111111:role/CloudScanIntanceRole"
        ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = "${aws_iam_role.CloudScanRole.name}"
  policy_arn = "${aws_iam_policy.cloudscan.arn}"
}

resource "aws_iam_policy" "cloudscan" {
  name        = "CloudScanRolePolicy"
  path        = "/"
  description = "CloudScan Policy for Operations."

  policy = <<EOF
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Action": [
                  "ec2:describeinstances",
                  "ec2:describenetworkinterfaces",
                  "elasticloadbalancing:describeloadbalancers",
                  "iam:getgroup",
                  "iam:getrole",
                  "iam:getrolepolicy",
                  "iam:getuser",
                  "iam:getuserpolicy",
                  "iam:GenerateCredentialReport",
                  "iam:listattachedgrouppolicies",
                  "iam:listattachedrolepolicies",
                  "iam:listattacheduserpolicies",
                  "iam:listgrouppolicies",
                  "iam:listgroups",
                  "iam:listpolicies",
                  "iam:listrolepolicies",
                  "iam:listroles",
                  "iam:listuserpolicies",
                  "iam:listusers",
                  "rds:describedbinstances",
                  "s3:getbucketacl",
                  "s3:getbucketcors",
                  "s3:getbucketlocation",
                  "s3:getbucketpolicy",
                  "s3:getbucketpolicystatus",
                  "s3:listbucket",
                  "s3:listallmybuckets"
              ],
              "Effect": "Allow",
              "Resource": "*"
          }
      ]
  }
EOF
}
