// IAM Polcies needed for Cloudscan to function.

// IAM Instance Role
resource "aws_iam_role" "CloudScanInstanceRole" {
  name = "CloudScanInstanceRole"

  assume_role_policy = <<EOF
{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Sid": "",
              "Effect": "Allow",
              "Principal": {
                  "Service": "ec2.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
          }
      ]
}
EOF
}
  
resource "aws_iam_role_policy_attachment" "attachinstance" {
  role       = aws_iam_role.CloudScanInstanceRole.name
  policy_arn = aws_iam_policy.CloudscanInstancePolicy.arn
}

resource "aws_iam_policy" "CloudscanInstancePolicy" {
  name        = "CloudscanInstancePolicy"
  path        = "/"
  description = "CloudScan Instance Policy for Operations."

  policy = <<EOF
{
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": "sts:AssumeRole",
              "Resource": [
                  "arn:aws:iam::11111111111:role/CloudScanRole",
                  "arn:aws:iam::11111111111:role/CloudScanInstanceRole"
              ]
          }
      ]
}
EOF
}

// Role defined in the Account that provides cloudscan permissions to audit.
resource "aws_iam_role" "CloudScanRole" {
  name = "CloudScanRole"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::11111111111:role/CloudScanInstanceRole"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.CloudScanRole.name
  policy_arn = aws_iam_policy.cloudscan.arn
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

resource "aws_iam_instance_profile" "CloudScanInstanceProfile" {
  name = "CloudScanInstanceProfile"
  role = aws_iam_role.CloudScanInstanceRole.name
}
