package security

import future.keywords.if
import future.keywords.in

# Default deny rule
default allow = false

# Allow if no violations found
allow if count(violations) == 0

# Security violations
violations contains violation if {
    # Check for critical vulnerabilities
    some finding
    finding := input.findings[_]
    finding.severity == "critical"
    violation := {
        "type": "critical_vulnerability",
        "message": sprintf("Critical vulnerability found: %v", [finding.title]),
        "finding": finding
    }
}

violations contains violation if {
    # Check for exposed secrets
    some secret
    secret := input.secrets[_]
    secret.severity == "critical"
    violation := {
        "type": "exposed_secret",
        "message": sprintf("Exposed secret detected: %v", [secret.secret_type]),
        "secret": secret
    }
}

violations contains violation if {
    # Check for insecure infrastructure
    some infra
    infra := input.infrastructure[_]
    infra.critical_issues > 0
    violation := {
        "type": "insecure_infrastructure",
        "message": sprintf("Insecure infrastructure detected in %v", [infra.file_path]),
        "infrastructure": infra
    }
}

violations contains violation if {
    # Check for vulnerable containers
    some container
    container := input.containers[_]
    container.critical_vulnerabilities > 0
    violation := {
        "type": "vulnerable_container",
        "message": sprintf("Vulnerable container detected: %v", [container.image_name]),
        "container": container
    }
}

# Compliance checks
compliance_violations contains violation if {
    # Check for missing security headers
    some header
    header := input.headers[_]
    not header.required
    violation := {
        "type": "missing_security_header",
        "message": sprintf("Missing required security header: %v", [header.name]),
        "header": header
    }
}

compliance_violations contains violation if {
    # Check for weak encryption
    some encryption
    encryption := input.encryption[_]
    encryption.algorithm == "md5" || encryption.algorithm == "sha1"
    violation := {
        "type": "weak_encryption",
        "message": sprintf("Weak encryption algorithm detected: %v", [encryption.algorithm]),
        "encryption": encryption
    }
}

# Security score calculation
security_score = score if {
    total_checks := count(input.findings) + count(input.secrets) + count(input.infrastructure) + count(input.containers)
    passed_checks := total_checks - count(violations)
    score := round((passed_checks / total_checks) * 100)
}

# Policy enforcement rules
enforce_policy(policy_name, resource) = result if {
    policy := input.policies[policy_name]
    policy.enabled
    result := {
        "enforced": true,
        "policy": policy_name,
        "resource": resource,
        "compliant": check_compliance(policy, resource)
    }
}

check_compliance(policy, resource) = compliant if {
    # Check if resource meets policy requirements
    compliant := true
    some rule
    rule := policy.rules[_]
    not rule_satisfied(rule, resource)
    compliant := false
}

rule_satisfied(rule, resource) if {
    rule.type == "no_critical_vulns"
    resource.critical_vulnerabilities == 0
}

rule_satisfied(rule, resource) if {
    rule.type == "encryption_required"
    resource.encrypted == true
}

rule_satisfied(rule, resource) if {
    rule.type == "access_control"
    resource.access_control_enabled == true
}

# Risk assessment
risk_assessment = assessment if {
    critical_risk := count([v | v := violations[_]; v.type == "critical_vulnerability"])
    high_risk := count([v | v := violations[_]; v.type == "exposed_secret"])
    medium_risk := count([v | v := violations[_]; v.type == "insecure_infrastructure"])
    low_risk := count([v | v := violations[_]; v.type == "vulnerable_container"])
    
    total_risk_score := (critical_risk * 10) + (high_risk * 5) + (medium_risk * 2) + low_risk
    
    assessment := {
        "risk_level": calculate_risk_level(total_risk_score),
        "risk_score": total_risk_score,
        "critical_issues": critical_risk,
        "high_issues": high_risk,
        "medium_issues": medium_risk,
        "low_issues": low_risk
    }
}

calculate_risk_level(score) = level if {
    score >= 20
    level := "critical"
} else = level if {
    score >= 10
    level := "high"
} else = level if {
    score >= 5
    level := "medium"
} else {
    level := "low"
}

# Deployment approval rules
deployment_approved = approved if {
    # Allow deployment if security score is above threshold
    security_score >= 80
    count(violations) == 0
    approved := true
} else {
    approved := false
}

# Security recommendations
security_recommendations = recommendations if {
    recommendations := [
        rec |
        some violation
        violation := violations[_]
        rec := generate_recommendation(violation)
    ]
}

generate_recommendation(violation) = recommendation if {
    violation.type == "critical_vulnerability"
    recommendation := {
        "priority": "high",
        "action": "Fix critical vulnerability immediately",
        "description": "Address the critical security vulnerability before deployment",
        "violation": violation
    }
} else = recommendation if {
    violation.type == "exposed_secret"
    recommendation := {
        "priority": "critical",
        "action": "Remove exposed secret and rotate credentials",
        "description": "Immediately remove the exposed secret and rotate all related credentials",
        "violation": violation
    }
} else = recommendation if {
    violation.type == "insecure_infrastructure"
    recommendation := {
        "priority": "high",
        "action": "Fix infrastructure security issues",
        "description": "Address the infrastructure security configuration issues",
        "violation": violation
    }
} else {
    recommendation := {
        "priority": "medium",
        "action": "Review and fix security issue",
        "description": "Review and address the security issue before deployment",
        "violation": violation
    }
} 