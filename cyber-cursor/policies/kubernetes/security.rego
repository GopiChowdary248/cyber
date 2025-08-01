package kubernetes.security

import future.keywords.if
import future.keywords.in

# Kubernetes security violations
kubernetes_violations contains violation if {
    # Check for containers running as root
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    container.securityContext.runAsNonRoot == false
    violation := {
        "type": "container_as_root",
        "message": "Container should not run as root",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "high"
    }
}

kubernetes_violations contains violation if {
    # Check for containers with privileged access
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    container.securityContext.privileged == true
    violation := {
        "type": "privileged_container",
        "message": "Container should not run in privileged mode",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "critical"
    }
}

kubernetes_violations contains violation if {
    # Check for containers without resource limits
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    not container.resources.limits
    violation := {
        "type": "no_resource_limits",
        "message": "Container should have resource limits defined",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "medium"
    }
}

kubernetes_violations contains violation if {
    # Check for containers with host network access
    some pod
    pod := input.kind[_].spec.template.spec
    pod.hostNetwork == true
    violation := {
        "type": "host_network_access",
        "message": "Pod should not use host network",
        "resource": input.metadata.name,
        "severity": "high"
    }
}

kubernetes_violations contains violation if {
    # Check for containers with host path volumes
    some volume
    volume := input.kind[_].spec.template.spec.volumes[_]
    volume.hostPath
    violation := {
        "type": "host_path_volume",
        "message": "Pod should not use host path volumes",
        "resource": input.metadata.name,
        "volume": volume.name,
        "severity": "high"
    }
}

kubernetes_violations contains violation if {
    # Check for containers without security context
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    not container.securityContext
    violation := {
        "type": "no_security_context",
        "message": "Container should have security context defined",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "medium"
    }
}

kubernetes_violations contains violation if {
    # Check for containers with default service account
    some serviceAccount
    serviceAccount := input.kind[_].spec.template.spec.serviceAccountName
    serviceAccount == "default"
    violation := {
        "type": "default_service_account",
        "message": "Pod should not use default service account",
        "resource": input.metadata.name,
        "severity": "medium"
    }
}

kubernetes_violations contains violation if {
    # Check for containers with latest tag
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    endswith(container.image, ":latest")
    violation := {
        "type": "latest_image_tag",
        "message": "Container should not use latest tag",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "medium"
    }
}

kubernetes_violations contains violation if {
    # Check for containers without liveness probe
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    not container.livenessProbe
    violation := {
        "type": "no_liveness_probe",
        "message": "Container should have liveness probe",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "low"
    }
}

kubernetes_violations contains violation if {
    # Check for containers without readiness probe
    some container
    container := input.kind[_].spec.template.spec.containers[_]
    not container.readinessProbe
    violation := {
        "type": "no_readiness_probe",
        "message": "Container should have readiness probe",
        "resource": input.metadata.name,
        "container": container.name,
        "severity": "low"
    }
}

# Network policy violations
network_policy_violations contains violation if {
    # Check for pods without network policies
    input.kind == "Pod"
    not input.metadata.annotations["network-policy"]
    violation := {
        "type": "no_network_policy",
        "message": "Pod should have network policy applied",
        "resource": input.metadata.name,
        "severity": "medium"
    }
}

# RBAC violations
rbac_violations contains violation if {
    # Check for overly permissive roles
    input.kind == "Role"
    some rule
    rule := input.rules[_]
    rule.verbs[_] == "*"
    violation := {
        "type": "wildcard_permissions",
        "message": "Role should not have wildcard permissions",
        "resource": input.metadata.name,
        "severity": "high"
    }
}

rbac_violations contains violation if {
    # Check for cluster-admin binding
    input.kind == "ClusterRoleBinding"
    input.roleRef.name == "cluster-admin"
    violation := {
        "type": "cluster_admin_binding",
        "message": "Should not bind to cluster-admin role",
        "resource": input.metadata.name,
        "severity": "critical"
    }
}

# Compliance checks for Kubernetes
kubernetes_compliance_violations contains violation if {
    # Check for required labels
    required_labels := {"app", "version", "environment"}
    missing_labels := required_labels - object.keys(input.metadata.labels)
    count(missing_labels) > 0
    violation := {
        "type": "missing_required_labels",
        "message": sprintf("Missing required labels: %v", [missing_labels]),
        "resource": input.metadata.name,
        "severity": "low"
    }
}

kubernetes_compliance_violations contains violation if {
    # Check for namespace isolation
    input.metadata.namespace == "default"
    violation := {
        "type": "default_namespace",
        "message": "Resources should not be in default namespace",
        "resource": input.metadata.name,
        "severity": "low"
    }
}

# Kubernetes security score
kubernetes_security_score = score if {
    total_checks := count(input.kind) + count(input.metadata)
    violations := count(kubernetes_violations) + count(network_policy_violations) + count(rbac_violations) + count(kubernetes_compliance_violations)
    score := round(((total_checks - violations) / total_checks) * 100)
}

# Kubernetes deployment approval
kubernetes_deployment_approved = approved if {
    count(kubernetes_violations) == 0
    count(rbac_violations) == 0
    kubernetes_security_score >= 80
    approved := true
} else {
    approved := false
}

# Kubernetes security recommendations
kubernetes_recommendations = recommendations if {
    recommendations := [
        rec |
        some violation
        violation := kubernetes_violations[_]
        rec := generate_kubernetes_recommendation(violation)
    ]
}

generate_kubernetes_recommendation(violation) = recommendation if {
    violation.type == "container_as_root"
    recommendation := {
        "priority": "high",
        "action": "Set runAsNonRoot to true",
        "description": "Configure security context to prevent running as root",
        "example": |
            securityContext:
              runAsNonRoot: true
              runAsUser: 1000
    }
} else = recommendation if {
    violation.type == "privileged_container"
    recommendation := {
        "priority": "critical",
        "action": "Remove privileged mode",
        "description": "Disable privileged mode for security",
        "example": |
            securityContext:
              privileged: false
    }
} else = recommendation if {
    violation.type == "no_resource_limits"
    recommendation := {
        "priority": "medium",
        "action": "Add resource limits",
        "description": "Define CPU and memory limits",
        "example": |
            resources:
              limits:
                cpu: "500m"
                memory: "512Mi"
              requests:
                cpu: "250m"
                memory: "256Mi"
    }
} else = recommendation if {
    violation.type == "latest_image_tag"
    recommendation := {
        "priority": "medium",
        "action": "Use specific image tag",
        "description": "Pin to specific version for reproducibility",
        "example": "image: nginx:1.21.6"
    }
} else {
    recommendation := {
        "priority": "medium",
        "action": "Review and fix security issue",
        "description": "Address the security configuration issue",
        "violation": violation
    }
} 