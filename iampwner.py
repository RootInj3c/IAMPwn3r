import http.client
import datetime
import hashlib
import urllib
import hmac
import json
import urllib.parse
import xml.etree.ElementTree as ET

# common permissions for privilege escalation and lateral movement in GCP
gcp_risky_permissions = [
    
    # IAM Permissions
    "iam.roles.create",
    "iam.roles.delete",
    "iam.roles.update",
    "iam.roles.get",
    "iam.roles.list",
    "iam.serviceAccounts.create",
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.delete",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.list",
    "iam.serviceAccounts.update",
    "iam.serviceAccounts.keys.create",
    "iam.serviceAccounts.keys.delete",
    "iam.serviceAccounts.keys.get",
    "iam.serviceAccounts.keys.list",
    "iam.policies.get",
    "iam.policies.set",
    "iam.policy.get",
    "iam.policy.set",
    "iam.securityKeys.create",
    "iam.securityKeys.delete",

    # Compute Engine Permissions (Instance management)
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
    "compute.instances.list",
    "compute.instances.setMetadata",
    "compute.instances.setTags",
    "compute.instances.start",
    "compute.instances.stop",
    "compute.instances.update",
    "compute.instances.setMachineType",

    # GKE Permissions (Kubernetes)
    "container.clusters.create",
    "container.clusters.delete",
    "container.clusters.get",
    "container.clusters.list",
    "container.clusters.update",
    "container.clusters.setIamPolicy",
    "container.pods.get",
    "container.pods.list",
    "container.services.get",
    "container.services.list",

    # Cloud Storage Permissions (S3 Equivalent)
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.get",
    "storage.objects.list",
    "storage.buckets.create",
    "storage.buckets.delete",
    "storage.hmacKeys.create",
    "storage.buckets.get",
    "storage.buckets.list",

    # Pub/Sub Permissions (Messaging)
    "pubsub.topics.create",
    "pubsub.topics.delete",
    "pubsub.topics.get",
    "pubsub.topics.list",
    "pubsub.subscriptions.create",
    "pubsub.subscriptions.delete",
    "pubsub.subscriptions.get",
    "pubsub.subscriptions.list",

    # BigQuery Permissions (Data Analysis)
    "bigquery.jobs.create",
    "bigquery.jobs.get",
    "bigquery.jobs.list",
    "bigquery.tables.create",
    "bigquery.tables.delete",
    "bigquery.tables.get",
    "bigquery.tables.list",

    # Cloud Functions Permissions (Serverless)
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.delete",
    "cloudfunctions.functions.get",
    "cloudfunctions.functions.list",
    "cloudfunctions.functions.update",

    # Service Usage
    "serviceusage.apiKeys.create",
    "serviceusage.apiKeys.list",

    # Cloud SQL Permissions (Databases)
    "sql.instances.create",
    "sql.instances.delete",
    "sql.instances.get",
    "sql.instances.list",
    "sql.users.create",
    "sql.users.delete",
    "sql.users.get",
    "sql.users.list",

    # Org Policy
    "orgpolicy.policy.set",
    
    # Cloud Builds
    "cloudbuilds.builds.create",

    # Deployment Manager
    "deploymentmanager.deployments.create",

    # Cloud Scheduler
    "cloudscheduler.jobs.create",
    
    # Cloud Identity and Access Management (IAM)
    "cloudidentity.groups.create",
    "cloudidentity.groups.delete",
    "cloudidentity.groups.get",
    "cloudidentity.groups.list",
    "cloudidentity.groups.update",
    "cloudidentity.groups.memberships.create",
    "cloudidentity.groups.memberships.delete",
    "cloudidentity.groups.memberships.get",
    "cloudidentity.groups.memberships.list",

    # Network Permissions (VPC, VPN, Firewall)
    "compute.networks.create",
    "compute.networks.delete",
    "compute.networks.get",
    "compute.networks.list",
    "compute.firewalls.create",
    "compute.firewalls.delete",
    "compute.firewalls.get",
    "compute.firewalls.list",
    "compute.addresses.create",
    "compute.addresses.delete",
    "compute.addresses.get",
    "compute.addresses.list",

    # Monitoring Permissions (Cloud Monitoring)
    "monitoring.alertPolicies.create",
    "monitoring.alertPolicies.delete",
    "monitoring.alertPolicies.get",
    "monitoring.alertPolicies.list",
    "monitoring.alertPolicies.update",
    
    # App Engine Permissions (Web and App Management)
    "appengine.applications.create",
    "appengine.applications.delete",
    "appengine.applications.get",
    "appengine.applications.list",
    "appengine.services.create",
    "appengine.services.delete",
    "appengine.services.get",
    "appengine.services.list",
    "appengine.versions.create",
    "appengine.versions.delete",
    "appengine.versions.get",
    "appengine.versions.list",
    
    # Service Management Permissions
    "servicemanagement.services.create",
    "servicemanagement.services.delete",
    "servicemanagement.services.get",
    "servicemanagement.services.list",
    "servicemanagement.services.update",
    
    # Artifact Registry Permissions
    "artifactregistry.repositories.create",
    "artifactregistry.repositories.delete",
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.list",
    "artifactregistry.repositories.update",

    # Access Context Manager (for Privilege Escalation)
    "accesscontextmanager.accessPolicies.create",
    "accesscontextmanager.accessPolicies.delete",
    "accesscontextmanager.accessPolicies.get",
    "accesscontextmanager.accessPolicies.list",
    "accesscontextmanager.accessLevels.create",
    "accesscontextmanager.accessLevels.delete",
    "accesscontextmanager.accessLevels.get",
    "accesscontextmanager.accessLevels.list",
    "accesscontextmanager.accessLevels.update",
    
    # IAM Policy Binding (Escalation through Role Binding)
    "iam.policy.set",
    "iam.policy.get",
    "iam.roleBindings.create",
    "iam.roleBindings.delete",
    "iam.roleBindings.get",
    "iam.roleBindings.list",

    # Cloud Logging Permissions (which may contain sensitive data)
    "logging.entries.list",
    "logging.sinks.get",
    "logging.sinks.list"
]

# read-only permissions that can be used by an attacker
# to gather information for lateral movement or privilege escalation
ro_permissions = [
    
    # IAM (Identity and Access Management)
    "iam:ListUsers",
    "iam:ListRoles",
    "iam:GetUser",
    "iam:GetRole",
    "iam:ListAttachedUserPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedGroupPolicies",
    "iam:GetUserPolicy",
    "iam:GetRolePolicy",
    "iam:ListAccessKeys",
    "iam:ListGroupsForUser",
    "iam:ListUsersForGroup",
    "iam:Get*",
    "iam:List*",
    "iam:Describe*",

    # EC2 (Elastic Compute Cloud)
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeKeyPairs",
    "ec2:DescribeVolumes",
    "ec2:DescribeSnapshots",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeImages",

    # S3 (Simple Storage Service)
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:GetObject",
    "s3:GetBucketPolicy",
    "s3:GetBucketAcl",
    "s3:ListBucketVersions",
    "s3:GetBucketLocation",
    "s3:ListObjects",
    "s3:ListObjectsV2",
    "s3:GetObjectVersion",
    "s3:GetBucketLogging",
    "s3:GetBucketWebsite",
    "s3:GetBucketLifecycle",
    "s3:GetBucketCors",
    "s3:GetBucketVersioning",
    "s3:GetBucketNotification",
    "s3:GetBucketRequestPayment",
    "s3:Get*",
    "s3:List*",
    "s3:Describe*",

    # Lambda
    "lambda:ListFunctions",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "lambda:ListEventSourceMappings",
    "lambda:ListVersionsByFunction",
    "lambda:Get*",
    "lambda:List*",
    "lambda:Describe*",

    # CloudTrail
    "cloudtrail:LookupEvents",
    "cloudtrail:DescribeTrails",
    "cloudtrail:ListPublicKeys",

    # VPC (Virtual Private Cloud)
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeRouteTables",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcPeeringConnections",
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeNatGateways",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeDhcpOptions",
    "ec2:DescribeCustomerGateways",
    "ec2:DescribeVpnConnections",
    "ec2:Get*",
    "ec2:List*",
    "ec2:Describe*",

    # RDS (Relational Database Service)
    "rds:DescribeDBInstances",
    "rds:DescribeDBClusters",
    "rds:DescribeDBSnapshots",
    "rds:DescribeDBParameterGroups",
    "rds:DescribeDBClusterSnapshots",
    "rds:DescribeDBSubnetGroups",
    "rds:DescribeOptionGroups",
    "rds:DescribeDBClusters",
    "rds:Get*",
    "rds:List*",
    "rds:Describe*",

    # CloudFormation
    "cloudformation:DescribeStacks",
    "cloudformation:DescribeStackResources",
    "cloudformation:DescribeStackEvents",
    "cloudformation:ListStackResources",

    # Secrets Manager
    "secretsmanager:ListSecrets",
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret",
    "secretsmanager:Get*",

    # SQS (Simple Queue Service)
    "sqs:ListQueues",
    "sqs:ListQueueTags",
    "sqs:GetQueueAttributes",
    "sqs:ListQueueAttributes",
    "sqs:Get*",
    "sqs:List*",
    "sqs:Describe*",

    # SNS (Simple Notification Service)
    "sns:ListTopics",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    "sns:Get*",
    "sns:List*",

    # IAM Access Analyzer
    "access-analyzer:ListFindings",
    "access-analyzer:ListAnalyzers",

    # KMS (Key Management Service)
    "kms:ListAliases",
    "kms:DescribeKey",
    "kms:ListKeys",
    "kms:ListGrants",
    "kms:GetKeyPolicy",
    "kms:Get*",
    "kms:List*",
    "kms:Describe*",

    # CloudWatch
    "cloudwatch:DescribeAlarms",
    "cloudwatch:ListMetrics",
    "cloudwatch:DescribeAnomalyDetectors",
    "cloudwatch:DescribeInsightRules",
    "cloudwatch:Get*",
    "cloudwatch:List*",

    # Route53
    "route53:ListHostedZones",
    "route53:ListResourceRecordSets",
    "route53:ListHealthChecks",
    "route53:ListGeoLocations",

    # S3-Object Lambda
    "s3-object-lambda:List*",
    "s3-object-lambda:Get*",

    # Systems Manager
    "ssm:DescribeParameters",
    "ssm:GetParameters",
    "ssm:GetParameter",
    "ssm:ListTagsForResource",
    "ssm:Get*",
    "ssm:List*",
    "ssm:Describe*",

    # Step Functions
    "states:ListStateMachines",
    "states:DescribeStateMachine",
    "states:ListExecutions",
    "states:DescribeExecution",
    "states:Get*",
    "states:List*",
    "states:Describe*",

    # AWS Config
    "config:DescribeConfigRules",
    "config:DescribeConfigurationAggregators",
    "config:DescribeConfigurationRecorderStatus",
    "config:DescribeDeliveryChannels",
    "config:DescribeComplianceByConfigRule",
    "config:DescribeComplianceByResource",

    # Elasticache
    "elasticache:DescribeCacheClusters",
    "elasticache:DescribeReplicationGroups",
    "elasticache:DescribeCacheParameterGroups",
    "elasticache:DescribeReservedNodes",

    # EKS (Elastic Kubernetes Service)
    "eks:ListClusters",
    "eks:DescribeCluster",
    "eks:ListNodegroups",
    "eks:DescribeNodegroup",
    "eks:Get*",
    "eks:List*",
    "eks:Describe*"
]

# IAM permissions that could be used
# for privilege escalation, lateral movement, or other attack vectors:

risky_permissions = [
    # Privilege Escalation
    "iam:PassRole",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:DeleteRole",
    "iam:DeleteUser",
    "iam:PutRolePolicy",
    "sts:AssumeRole",
    "iam:AttachUserPolicy",
    "iam:DetachUserPolicy",
    "iam:PutUserPolicy",
    "iam:DeleteAccessKey",
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    
    # EC2 Instance Compromise
    "ec2:RunInstances",
    "ec2:AssociateIamInstanceProfile",
    "ec2:TerminateInstances",
    "ec2:CreateTags",
    "ec2:DescribeInstances",
    "ec2:DescribeImages",
    "ec2:ModifyInstanceAttribute",
    "ec2:RebootInstances",
    
    # S3 Bucket & Object Permissions
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket",
    "s3:DeleteObject",
    "s3:CreateBucket",
    "s3:PutBucketPolicy",
    "s3:GetBucketPolicy",
    "s3:DeleteBucket",
    "s3:ListBucketVersions",
    
    # Lambda Function Execution
    "lambda:InvokeFunction",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:DeleteFunction",
    
    # Secrets Management & KMS
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "kms:Decrypt",
    "kms:Encrypt",
    "kms:GenerateDataKey",
    "kms:RevokeGrant",
    
    # CloudTrail & CloudWatch Logs
    "cloudtrail:StartLogging",
    "cloudtrail:StopLogging",
    "cloudtrail:DescribeTrails",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
    
    # RDS & Database Access
    "rds:DescribeDBInstances",
    "rds:CreateDBInstance",
    "rds:ModifyDBInstance",
    "rds:DeleteDBInstance",
    
    # IAM User & Role Enumeration
    "iam:ListUsers",
    "iam:ListRoles",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListRolePolicies",
    "iam:ListUserPolicies",
    "iam:GetUser",
    "iam:GetRole",
    
    # Auto Scaling & EC2 Instance Management
    "autoscaling:UpdateAutoScalingGroup",
    "autoscaling:CreateAutoScalingGroup",
    "autoscaling:DeleteAutoScalingGroup",
    
    # EC2 Key Pairs & Metadata Access
    "ec2:CreateKeyPair",
    "ec2:ImportKeyPair",
    "ec2:DeleteKeyPair",
    "ec2:DescribeKeyPairs",
    
    # IAM Role & Trust Policy Management
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",

    # RDS Permissions (privilege escalation & lateral movement)
    "rds:DescribeDBInstances",
    "rds:CreateDBInstance",
    "rds:ModifyDBInstance",
    "rds:DeleteDBInstance",
    "rds:CreateDBCluster",
    "rds:DeleteDBCluster",
    "rds:DescribeDBClusters",
    "rds:ModifyDBCluster",
    "rds:RebootDBInstance",
    "rds:DescribeDBSecurityGroups",
    "rds:DescribeDBParameterGroups",
    "rds:CreateDBSecurityGroup",
    "rds:AuthorizeDBSecurityGroupIngress",
    "rds:RevokeDBSecurityGroupIngress",
    "rds:DeleteDBSecurityGroup",
    "rds:DescribeDBSnapshots",
    "rds:CreateDBSnapshot",
    "rds:DeleteDBSnapshot",
    "rds:CopyDBSnapshot",
    "rds:ModifyDBSnapshot",
    "rds:DescribeDBSubnetGroups",
    "rds:CreateDBSubnetGroup",
    "rds:ModifyDBSubnetGroup",
    "rds:DeleteDBSubnetGroup",

    # VPC Permissions (lateral movement, network manipulation, attack paths)
    "ec2:CreateVPC",
    "ec2:DeleteVPC",
    "ec2:DescribeVpcs",
    "ec2:CreateSubnet",
    "ec2:DeleteSubnet",
    "ec2:DescribeSubnets",
    "ec2:CreateSecurityGroup",
    "ec2:DeleteSecurityGroup",
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:ModifyInstanceAttribute",
    "ec2:AssociateSecurityGroup",
    "ec2:DescribeInstances",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "ec2:CreateKeyPair",
    "ec2:ImportKeyPair",
    "ec2:DescribeKeyPairs",
    "ec2:ModifyVpcAttribute",
    "ec2:CreateInternetGateway",
    "ec2:DeleteInternetGateway",
    "ec2:AttachInternetGateway",
    "ec2:DetachInternetGateway",
    "ec2:CreateNATGateway",
    "ec2:DeleteNATGateway",
    "ec2:DescribeNATGateways",
    "ec2:DescribeRouteTables",
    "ec2:CreateRoute",
    "ec2:DeleteRoute",
    "ec2:AssociateRouteTable",
    "ec2:DisassociateRouteTable",
    "ec2:CreateVPNGateway",
    "ec2:DeleteVPNGateway",
    "ec2:DescribeVPNGateways",
    "ec2:CreateCustomerGateway",
    "ec2:DeleteCustomerGateway",
    "ec2:DescribeCustomerGateways",
    "ec2:CreateVPNConnection",
    "ec2:DeleteVPNConnection",
    
    # Lambda Permissions (privilege escalation, lateral movement, data exfiltration)
    "lambda:InvokeFunction",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:DeleteFunction",
    "lambda:ListFunctions",
    "lambda:GetFunction",
    "lambda:GetFunctionConfiguration",
    "lambda:PutFunctionConcurrency",
    "lambda:DeleteFunctionConcurrency",
    "lambda:AddLayerVersionPermission",
    "lambda:RemoveLayerVersionPermission",
    "lambda:PublishLayerVersion",
    "lambda:UpdateEventSourceMapping",
    "lambda:CreateEventSourceMapping",
    "lambda:DeleteEventSourceMapping",
    "lambda:ListEventSourceMappings",
    "lambda:TagResource",
    "lambda:UntagResource",
    "lambda:InvokeAsync",
    "lambda:ListTags",
    
    # VPC Lambda Integration (privilege escalation through networking)
    "ec2:AssociateVpcCidrBlock",
    "ec2:DisassociateVpcCidrBlock",
    "ec2:ModifyVpcTenancy",
    "ec2:CreateFlowLog",
    "ec2:DeleteFlowLog",
    "ec2:DescribeFlowLogs",
    "ec2:AssociateVpcPeeringConnection",
    "ec2:CreateVpcPeeringConnection",
    "ec2:DeleteVpcPeeringConnection",
    "ec2:DescribeVpcPeeringConnections",
    
    # IAM Permissions for Lambda Roles (impersonation, privilege escalation)
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:PutRolePolicy",
    "iam:DeleteRolePolicy",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole"
]

#### GCP Stuff ####

def test_gcp_permissions(resource, access_token):
    api_url = f"https://cloudresourcemanager.googleapis.com/v1/{resource}:testIamPermissions"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    body = {
        "permissions": gcp_risky_permissions
    }
    response_data = send_request(api_url, body, headers)
    
    if response_data:
        try:
            response_json = json.loads(response_data)
            applied_permissions = response_json.get('permissions', [])
            for perm in applied_permissions:
                print(f"✅ Abusable PERM ALLOWED: {perm}")
        except json.JSONDecodeError as e:
            #print(f"Error decoding response: {e}")
            return []
    else:
        #print("No response received.")
        return []

### AWS Stuff ###
    
policiesARN = []
aws_access_key = None
aws_secret_key = None

# AWS STS & IAM Endpoints
sts_host = "sts.amazonaws.com"
iam_host = "iam.amazonaws.com"
region = "us-east-1"

# AWS Signature Version 4 Helpers
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, "aws4_request")
    return k_signing

# Get Current UTC Timestamp
t = datetime.datetime.now(datetime.UTC)
amz_date = t.strftime("%Y%m%dT%H%M%SZ")
date_stamp = t.strftime("%Y%m%d")

### Get Caller Identity ###
def get_identity():
    payload = "Action=GetCallerIdentity&Version=2011-06-15"
    headers = get_signed_headers(sts_host, payload, "sts")
    
    response_data = send_request(sts_host, payload, headers)
    root = ET.fromstring(response_data)

    arn = root.find(".//{*}Arn").text  # Extract ARN
    user_id = root.find(".//{*}UserId").text
    account_id = root.find(".//{*}Account").text

    if "role/" in arn:
        role_name = arn.split("/")[-1]
        return {"type": "role", "name": role_name}
    else:
        user_name = arn.split("/")[-1]
        return {"type": "user", "name": user_name}

### List Role Policies ###
def list_role_policies(role_name):
    payload = f"Action=ListAttachedRolePolicies&Version=2010-05-08&RoleName={role_name}"
    headers = get_signed_headers(iam_host, payload, "iam")
    
    response_data = send_request(iam_host, payload, headers)
    root = ET.fromstring(response_data)

    if "AccessDenied" in response_data:
        return "AccessDenied"
    else:
        policiesARN = [policy.find(".//{*}PolicyArn").text for policy in root.findall(".//{*}AttachedPolicy")]
        policies = [policy.find(".//{*}PolicyName").text for policy in root.findall(".//{*}AttachedPolicy")]
        return policies

### List User Groups ###
def list_user_groups(user_name):
    print(f"🔍 Listing groups for user: {user_name}")  # Debugging line
    payload = f"Action=ListGroupsForUser&Version=2010-05-08&UserName={user_name}"
    headers = get_signed_headers(iam_host, payload, "iam")
    
    response_data = send_request(iam_host, payload, headers)
    
    root = ET.fromstring(response_data)

    if "AccessDenied" in response_data:
        return "AccessDenied"
    else:
        # Check if the response contains any groups
        groups = []
        for group in root.findall(".//{*}Groups/{*}member"):
            group_name = group.find("{*}GroupName").text
            if group_name:
                groups.append(group_name)
        
        if not groups:
            return "No groups found"  # Return a clearer message if no groups are found
        return groups

def list_group_policies(group_name, returnARN=False):
    print(f"🔍 Listing policies for group: {group_name}")  # Debugging line
    payload = f"Action=ListAttachedGroupPolicies&Version=2010-05-08&GroupName={group_name}"
    headers = get_signed_headers(iam_host, payload, "iam")
    
    response_data = send_request(iam_host, payload, headers)
    
    # Parse the XML response
    root = ET.fromstring(response_data)
    
    # Extract the namespace
    namespace = {'ns': 'https://iam.amazonaws.com/doc/2010-05-08/'}
    
    # Extract <AttachedPolicies> section and parse each <member>
    policies = []
    attached_policies = root.findall(".//ns:AttachedPolicies/ns:member", namespace)
    
    for policy in attached_policies:
        policy_arn = policy.find("ns:PolicyArn", namespace).text.strip() if policy.find("ns:PolicyArn", namespace) is not None else None
        policy_name = policy.find("ns:PolicyName", namespace).text.strip() if policy.find("ns:PolicyName", namespace) is not None else None
        if policy_arn and policy_name:
            policies.append({"PolicyArn": policy_arn, "PolicyName": policy_name})
    
    if not policies:
        return "No policies found"
    
    # Extract the policy names for display purposes
    if returnARN:
        policy_names = [policy["PolicyArn"] for policy in policies]
    else:
        policy_names = [policy["PolicyName"] for policy in policies]
    
    return policy_names  # Return just the policy names

def get_latest_policy_version(policy_arn):
    payload = f"Action=ListPolicyVersions&Version=2010-05-08&PolicyArn={policy_arn}"
    headers = get_signed_headers(iam_host, payload, "iam")
    
    response_data = send_request(iam_host, payload, headers)
   
    root = ET.fromstring(response_data)
    
    latest_version = None
    for version in root.findall(".//{*}Versions/{*}member"):
        is_default = version.find("{*}IsDefaultVersion").text.strip()
        version_id = version.find("{*}VersionId").text.strip()

        if is_default == "true":
            latest_version = version_id
            break

#    if latest_version:
#        print(f"Latest version ID: {latest_version}") 
#    else:
#        print("No default version found")

    return latest_version

def get_policy_document(policy_arn):
    # Fetch the latest policy version
    latest_version = get_latest_policy_version(policy_arn)
    
    if not latest_version:
        return {}

    # Use the latest version ID to get the policy document
    payload = f"Action=GetPolicyVersion&Version=2010-05-08&PolicyArn={policy_arn}&VersionId={latest_version}"
    headers = get_signed_headers(iam_host, payload, "iam")
    
    response_data = send_request(iam_host, payload, headers)    
    root = ET.fromstring(response_data)

    # Extract policy document and decode it from JSON
    policy_doc = root.find(".//{*}Document").text.strip() if root.find(".//{*}Document") is not None else None
    if not policy_doc:
        return {}
    
    document_decoded = urllib.parse.unquote(policy_doc)
    
    if document_decoded:
        return json.loads(document_decoded)
    
    return {}

def check_arn_permissions(arn_name):

    allowed_permissions = set()
    
    # Fetch the policy document
    policy_doc = get_policy_document(arn_name)
    if "Statement" in policy_doc:
        for statement in policy_doc["Statement"]:
            if "Action" in statement:
                actions = statement["Action"]
                if isinstance(actions, str):
                    allowed_permissions.add(actions)
                else:
                    allowed_permissions.update(actions)
                 
    for perm in allowed_permissions:
        if perm in ro_permissions:
            print(f"✅ ReadOnly PERM ALLOWED: {perm}")
        elif perm in risky_permissions:
            print(f"✅ RISKY PERM ALLOWED: {perm}")
        else:
            continue
        
def check_role_permissions(role_name, required_permissions):
    attached_policies = list_role_policies(role_name)
    
    allowed_permissions = set()
    
    for policy_arn in attached_policies:
        policy_doc = get_policy_document(policy_arn)
        
        if "Statement" in policy_doc:
            for statement in policy_doc["Statement"]:
                if "Action" in statement:
                    actions = statement["Action"]
                    if isinstance(actions, str):
                        allowed_permissions.add(actions.lower())
                    else:
                        allowed_permissions.update([a.lower() for a in actions])
    
    for perm in allowed_permissions:
        if perm in ro_permissions:
            print(f"✅ ReadOnly PERM ALLOWED: {perm}")
        elif perm in risky_permissions:
            print(f"✅ RISKY PERM ALLOWED: {perm}")
        else:
            continue

def get_signed_headers(host, payload, service):
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    canonical_request = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    signing_key = get_signature_key(aws_secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"AWS4-HMAC-SHA256 Credential={aws_access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": authorization_header,
        "Content-Type": "application/x-www-form-urlencoded"
    }

def send_request(host, payload, headers):
    conn = http.client.HTTPSConnection(host)
    conn.request("POST", "/", payload, headers)
    response = conn.getresponse()
    response_data = response.read().decode()
    conn.close()
    return response_data

def draw_dynamic_table(headers, data):
    """
    Draws a dynamic ASCII table with headers and data.
    
    :param headers: List of strings representing the column headers.
    :param data: List of lists, where each inner list represents a row of data.
    """
    # Determine the maximum width for each column
    col_widths = [max(len(str(item)) for item in col) for col in zip(*([headers] + data))]
    
    # Print the top border
    print('+' + '+'.join(['-' * (width + 2) for width in col_widths]) + '+')
    
    # Print the header row
    print('|' + '|'.join([headers[i].ljust(col_widths[i] + 2) for i in range(len(headers))]) + '|')
    
    # Print the separator
    print('+' + '+'.join(['-' * (width + 2) for width in col_widths]) + '+')
    
    # Print the data rows
    for row in data:
        print('|' + '|'.join([str(row[i]).ljust(col_widths[i] + 2) for i in range(len(row))]) + '|')
    
    # Print the bottom border
    print('+' + '+'.join(['-' * (width + 2) for width in col_widths]) + '+')
    
def runAWS():
    identity = get_identity()
    if identity["type"] == "role":
        print(f"✅ Running as IAM Role: {identity['name']}")
        policies = list_role_policies(identity["name"])
        if groups == "AccessDenied":
            print("⚠ No iam:ListAttachedRolePolicies permissions to this user.")
        elif policies:
            print(f"🔹 Role Policies: {', '.join(policies)}")
            for role in policies:
                check_role_permissions(role, required_permissions)
        else:
            print("⚠ No policies attached to this role.")

    elif identity["type"] == "user":
        print(f"✅ Running as IAM User: {identity['name']} (No IAM Role)")
        
        groups = list_user_groups(identity["name"])
        if groups == "AccessDenied":
            print("⚠ No iam:ListGroupsForUser permissions to this user.")
        elif groups:
            print(f"🔹 User Groups: {', '.join(groups)}")
            for group in groups:
                group_policies = list_group_policies(group)
                if groups == "AccessDenied":
                        print("⚠ No iam:ListAttachedGroupPolicies permissions to this user.")            
                elif group_policies:
                    print(f"🔸 Group '{group}' Policies: {', '.join(group_policies)}")
                    for ArnPolicy in list_group_policies(group, True):
                        check_arn_permissions(ArnPolicy)
                else:
                    print(f"⚠ No policies attached to group '{group}'.")
        else:
            print("⚠ No groups assigned to this user.")


while True:
    cmd = input("IAMPWn3r >> ").strip().lower()
    if cmd in ["help", "h"]:
        headers = ["Command", "Description", "Category"]
        data = [
            ["gcp", "Run GCP IAM enumeration", "Checker"],
            ["azure", "Run Azure IAM enumeration", "Checker"],
            ["aws", "Run AWS IAM enumeration", "Checker"],
        ]
        draw_dynamic_table(headers, data)
    elif cmd == "aws":
        chk = input("Do you have an access token and account Id? (Y/N): ").strip().lower()
        if chk != "y":
            print("Exiting...")
            break
        else:
            ak = input("Accses Key: ")
            aws_access_key = ak.strip()
            if ak is None:
                print("Empty Key, Exiting...")
                break
            sk = input("Secret Key: ")
            aws_secret_key = sk.strip()
            if sk is None:
                print("Empty Secret Key, Exiting...")
                break
            print("Running..")
            runAWS()
    elif cmd == "exit":
        print("Exiting...")
        break
    else:
        print(f"Unknown command: {cmd}")


