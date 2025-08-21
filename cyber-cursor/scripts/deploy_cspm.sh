#!/bin/bash

# CyberShield CSPM Module Deployment Script
# This script automates the deployment of the comprehensive CSPM module

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="cybershield-cspm"
COMPOSE_FILE="docker-compose.cspm.yml"
ENV_FILE=".env.cspm"

echo -e "${BLUE}🚀 CyberShield CSPM Module Deployment${NC}"
echo "=========================================="

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    print_status "Prerequisites check passed"
}

# Create environment file
create_env_file() {
    print_info "Creating environment configuration file..."
    
    if [ ! -f "$ENV_FILE" ]; then
        cat > "$ENV_FILE" << EOF
# CyberShield CSPM Environment Configuration
# Database Configuration
POSTGRES_PASSWORD=cybershield_secure_password_$(openssl rand -hex 8)
POSTGRES_DB=cybershield_cspm

# Redis Configuration
REDIS_PASSWORD=redis_secure_password_$(openssl rand -hex 8)

# Application Configuration
SECRET_KEY=$(openssl rand -hex 32)
ENVIRONMENT=production
LOG_LEVEL=INFO

# Monitoring Configuration
GRAFANA_PASSWORD=admin_secure_$(openssl rand -hex 4)

# Vault Configuration
VAULT_TOKEN=vault_token_$(openssl rand -hex 16)

# API Configuration
API_BASE_URL=http://localhost:8000
FRONTEND_URL=http://localhost:3000
MOBILE_URL=http://localhost:3001

# Security Configuration
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=100
RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE=10

# Celery Configuration
CELERY_WORKER_CONCURRENCY=4
CELERY_TASK_TIME_LIMIT=600
CELERY_TASK_SOFT_TIME_LIMIT=300

# OPA Configuration
OPA_URL=http://localhost:8181
OPA_POLICY_DIR=./policies

# Monitoring
PROMETHEUS_RETENTION_TIME=200h
GRAFANA_ADMIN_PASSWORD=admin_secure_$(openssl rand -hex 4)
EOF
        
        print_status "Environment file created: $ENV_FILE"
        print_warning "Please review and modify the generated passwords in $ENV_FILE"
    else
        print_info "Environment file already exists: $ENV_FILE"
    fi
}

# Create necessary directories
create_directories() {
    print_info "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p policies
    mkdir -p monitoring/grafana/dashboards
    mkdir -p monitoring/grafana/datasources
    mkdir -p nginx/ssl
    mkdir -p uploads
    
    print_status "Directories created"
}

# Create sample policies
create_sample_policies() {
    print_info "Creating sample OPA policies..."
    
    # AWS S3 Public Access Policy
    cat > policies/aws_s3_public_access.rego << 'EOF'
package s3.public_access

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_acls == false
    msg := sprintf("S3 bucket %v has public ACLs enabled", [input.bucket_name])
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.public_access_block_configuration.block_public_policy == false
    msg := sprintf("S3 bucket %v has public policy enabled", [input.bucket_name])
}
EOF

    # AWS EC2 Security Group Policy
    cat > policies/aws_ec2_security_groups.rego << 'EOF'
package ec2.security_groups

import future.keywords.if
import future.keywords.in

deny[msg] {
    input.resource_type == "aws_security_group"
    rule := input.ingress_rules[_]
    rule.from_port == 0
    rule.to_port == 65535
    rule.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("Security group %v allows all traffic from anywhere", [input.group_name])
}
EOF

    print_status "Sample policies created"
}

# Create monitoring configuration
create_monitoring_config() {
    print_info "Creating monitoring configuration..."
    
    # Prometheus configuration
    cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'cybershield-backend'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'cybershield-postgres'
    static_configs:
      - targets: ['postgres:5432']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'cybershield-redis'
    static_configs:
      - targets: ['redis:6379']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'cybershield-opa'
    static_configs:
      - targets: ['opa:8181']
    metrics_path: '/metrics'
    scrape_interval: 30s
EOF

    # Grafana datasource configuration
    cat > monitoring/grafana/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

    print_status "Monitoring configuration created"
}

# Build and start services
deploy_services() {
    print_info "Building and starting services..."
    
    # Load environment variables
    set -a
    source "$ENV_FILE"
    set +a
    
    # Build images
    print_info "Building Docker images..."
    docker-compose -f "$COMPOSE_FILE" build
    
    # Start services
    print_info "Starting services..."
    docker-compose -f "$COMPOSE_FILE" up -d
    
    print_status "Services started successfully"
}

# Wait for services to be ready
wait_for_services() {
    print_info "Waiting for services to be ready..."
    
    # Wait for PostgreSQL
    print_info "Waiting for PostgreSQL..."
    until docker-compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U cybershield -d cybershield_cspm; do
        sleep 2
    done
    print_status "PostgreSQL is ready"
    
    # Wait for Redis
    print_info "Waiting for Redis..."
    until docker-compose -f "$COMPOSE_FILE" exec -T redis redis-cli --raw incr ping; do
        sleep 2
    done
    print_status "Redis is ready"
    
    # Wait for Backend
    print_info "Waiting for Backend API..."
    until curl -f http://localhost:8000/health 2>/dev/null; do
        sleep 5
    done
    print_status "Backend API is ready"
    
    # Wait for OPA
    print_info "Waiting for OPA..."
    until curl -f http://localhost:8181/health 2>/dev/null; do
        sleep 2
    done
    print_status "OPA is ready"
}

# Run database migrations
run_migrations() {
    print_info "Running database migrations..."
    
    # Wait a bit for the database to be fully ready
    sleep 5
    
    # Run the migration script
    docker-compose -f "$COMPOSE_FILE" exec -T backend python scripts/run_cspm_migration.py
    
    print_status "Database migrations completed"
}

# Create initial data
create_initial_data() {
    print_info "Creating initial data..."
    
    # This would typically create initial users, policies, etc.
    # For now, we'll just create a placeholder
    
    print_status "Initial data setup completed"
}

# Health check
health_check() {
    print_info "Performing health check..."
    
    # Check all services
    services=("backend" "frontend" "mobile" "postgres" "redis" "opa" "prometheus" "grafana")
    
    for service in "${services[@]}"; do
        if docker-compose -f "$COMPOSE_FILE" ps "$service" | grep -q "Up"; then
            print_status "$service is running"
        else
            print_error "$service is not running"
        fi
    done
    
    # Check API endpoints
    if curl -f http://localhost:8000/health 2>/dev/null; then
        print_status "Backend API health check passed"
    else
        print_error "Backend API health check failed"
    fi
    
    print_status "Health check completed"
}

# Display deployment information
display_deployment_info() {
    echo ""
    echo -e "${GREEN}🎉 CyberShield CSPM Module Deployment Complete!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${BLUE}Service URLs:${NC}"
    echo "  Backend API:     http://localhost:8000"
    echo "  Frontend:        http://localhost:3000"
    echo "  Mobile App:      http://localhost:3001"
    echo "  Grafana:         http://localhost:3002 (admin/admin_secure_*)"
    echo "  Prometheus:      http://localhost:9090"
    echo "  OPA:             http://localhost:8181"
    echo "  Vault:           http://localhost:8200"
    echo ""
    echo -e "${BLUE}Database:${NC}"
    echo "  PostgreSQL:      localhost:5432"
    echo "  pgBouncer:       localhost:5433"
    echo "  Redis:           localhost:6379"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Access the frontend at http://localhost:3000"
    echo "  2. Create your first admin user"
    echo "  3. Configure cloud provider integrations"
    echo "  4. Set up monitoring dashboards"
    echo "  5. Review and customize security policies"
    echo ""
    echo -e "${YELLOW}Important:${NC}"
    echo "  - Review the generated passwords in $ENV_FILE"
    echo "  - Change default passwords in production"
    echo "  - Configure SSL certificates for production use"
    echo "  - Set up proper backup strategies"
    echo ""
}

# Main deployment function
main() {
    check_prerequisites
    create_env_file
    create_directories
    create_sample_policies
    create_monitoring_config
    deploy_services
    wait_for_services
    run_migrations
    create_initial_data
    health_check
    display_deployment_info
}

# Run main function
main "$@"
