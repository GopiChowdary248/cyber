package terraform.security

import future.keywords.if
import future.keywords.in

# Terraform security violations
terraform_violations contains violation if {
    # Check for unencrypted storage
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not resource.change.after.encryption
    violation := {
        "type": "unencrypted_storage",
        "message": "S3 bucket must be encrypted",
        "resource": resource.address,
        "severity": "high"
    }
}

terraform_violations contains violation if {
    # Check for public access on S3 buckets
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.after.public_access_block_configuration.block_public_acls == false
    violation := {
        "type": "public_s3_access",
        "message": "S3 bucket has public access enabled",
        "resource": resource.address,
        "severity": "critical"
    }
}

terraform_violations contains violation if {
    # Check for unencrypted RDS instances
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.storage_encrypted == false
    violation := {
        "type": "unencrypted_database",
        "message": "RDS instance must be encrypted",
        "resource": resource.address,
        "severity": "high"
    }
}

terraform_violations contains violation if {
    # Check for security groups with overly permissive rules
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    some rule
    rule := resource.change.after.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    rule.from_port == 22
    violation := {
        "type": "permissive_security_group",
        "message": "Security group allows SSH from anywhere",
        "resource": resource.address,
        "severity": "high"
    }
}

terraform_violations contains violation if {
    # Check for IAM policies with wildcard permissions
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    some statement
    statement := resource.change.after.policy[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    violation := {
        "type": "wildcard_iam_permissions",
        "message": "IAM policy contains wildcard permissions",
        "resource": resource.address,
        "severity": "high"
    }
}

terraform_violations contains violation if {
    # Check for missing VPC configuration
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_lambda_function"
    not resource.change.after.vpc_config
    violation := {
        "type": "lambda_no_vpc",
        "message": "Lambda function should be in VPC for security",
        "resource": resource.address,
        "severity": "medium"
    }
}

terraform_violations contains violation if {
    # Check for unencrypted EBS volumes
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    resource.change.after.encrypted == false
    violation := {
        "type": "unencrypted_ebs",
        "message": "EBS volume must be encrypted",
        "resource": resource.address,
        "severity": "high"
    }
}

terraform_violations contains violation if {
    # Check for CloudTrail not enabled
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_cloudtrail"
    resource.change.after.enable_logging == false
    violation := {
        "type": "cloudtrail_disabled",
        "message": "CloudTrail logging must be enabled",
        "resource": resource.address,
        "severity": "medium"
    }
}

# Compliance checks for Terraform
terraform_compliance_violations contains violation if {
    # Check for required tags
    some resource
    resource := input.resource_changes[_]
    required_tags := {"Environment", "Project", "Owner"}
    missing_tags := required_tags - object.keys(resource.change.after.tags)
    count(missing_tags) > 0
    violation := {
        "type": "missing_required_tags",
        "message": sprintf("Missing required tags: %v", [missing_tags]),
        "resource": resource.address,
        "severity": "low"
    }
}

terraform_compliance_violations contains violation if {
    # Check for cost optimization
    some resource
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    resource.change.after.instance_type == "t2.micro"
    violation := {
        "type": "cost_optimization",
        "message": "Consider using t3.micro for better performance",
        "resource": resource.address,
        "severity": "low"
    }
}

# Terraform security score
terraform_security_score = score if {
    total_resources := count(input.resource_changes)
    violations := count(terraform_violations) + count(terraform_compliance_violations)
    score := round(((total_resources - violations) / total_resources) * 100)
}

# Terraform deployment approval
terraform_deployment_approved = approved if {
    count(terraform_violations) == 0
    terraform_security_score >= 85
    approved := true
} else {
    approved := false
}

# Terraform security recommendations
terraform_recommendations = recommendations if {
    recommendations := [
        rec |
        some violation
        violation := terraform_violations[_]
        rec := generate_terraform_recommendation(violation)
    ]
}

generate_terraform_recommendation(violation) = recommendation if {
    violation.type == "unencrypted_storage"
    recommendation := {
        "priority": "high",
        "action": "Enable encryption on S3 bucket",
        "description": "Add encryption configuration to the S3 bucket resource",
        "example": 'encryption { algorithm = "AES256" }'
    }
} else = recommendation if {
    violation.type == "public_s3_access"
    recommendation := {
        "priority": "critical",
        "action": "Disable public access on S3 bucket",
        "description": "Configure public access block settings",
        "example": 'public_access_block_configuration { block_public_acls = true }'
    }
} else = recommendation if {
    violation.type == "unencrypted_database"
    recommendation := {
        "priority": "high",
        "action": "Enable encryption on RDS instance",
        "description": "Set storage_encrypted = true",
        "example": 'storage_encrypted = true'
    }
} else {
    recommendation := {
        "priority": "medium",
        "action": "Review and fix security issue",
        "description": "Address the security configuration issue",
        "violation": violation
    }
} 