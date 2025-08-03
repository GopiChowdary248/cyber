#!/bin/bash

# RASP Backend Deployment Script for Linux/Unix
# Comprehensive deployment script for the RASP (Runtime Application Self-Protection) backend.
# Handles database initialization, environment setup, and service deployment.

set -e  # Exit on any error

# Default configuration
ENVIRONMENT=${ENVIRONMENT:-"development"}
DATABASE_HOST=${DATABASE_HOST:-"localhost"}
DATABASE_PORT=${DATABASE_PORT:-5432}
DATABASE_NAME=${DATABASE_NAME:-"cybershield"}
DATABASE_USER=${DATABASE_USER:-"cybershield_user"}
DATABASE_PASSWORD=${DATABASE_PASSWORD:-"cybershield_password"}
REDIS_HOST=${REDIS_HOST:-"localhost"}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_PASSWORD=${REDIS_PASSWORD:-"redis_password"}
API_PORT=${API_PORT:-8000}
USE_DOCKER=${USE_DOCKER:-false}
SKIP_TESTS=${SKIP_TESTS:-false}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Helper functions
print_step() {
    echo -e "\n${CYAN}🔧 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}$1${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Test port connectivity
test_port() {
    local host=$1
    local port=$2
    timeout 5 bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
}

# Test database connection
test_database_connection() {
    local host=$1
    local port=$2
    local database=$3
    local user=$4
    local password=$5
    
    PGPASSWORD=$password psql -h $host -p $port -U $user -d $database -c "SELECT 1;" >/dev/null 2>&1
}

# Initialize environment
initialize_environment() {
    print_step "Initializing deployment environment"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may require elevated privileges."
    fi
    
    # Create necessary directories
    mkdir -p logs
    mkdir -p uploads
    mkdir -p reports
    
    print_success "Environment initialized"
}

# Install system dependencies
install_dependencies() {
    print_step "Installing system dependencies"
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv postgresql-client redis-tools curl wget
        elif command_exists yum; then
            # CentOS/RHEL
            sudo yum update -y
            sudo yum install -y python3 python3-pip postgresql redis curl wget
        elif command_exists dnf; then
            # Fedora
            sudo dnf update -y
            sudo dnf install -y python3 python3-pip postgresql redis curl wget
        else
            print_error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists brew; then
            brew update
            brew install python postgresql redis curl wget
        else
            print_error "Homebrew not found. Please install Homebrew first."
            exit 1
        fi
    else
        print_error "Unsupported operating system"
        exit 1
    fi
    
    # Check Python
    if ! command_exists python3; then
        print_error "Python 3 is not installed"
        exit 1
    fi
    
    python_version=$(python3 --version)
    print_success "Python version: $python_version"
    
    # Check pip
    if ! command_exists pip3; then
        print_error "pip3 is not installed"
        exit 1
    fi
    
    # Check PostgreSQL client
    if ! command_exists psql; then
        print_warning "PostgreSQL client (psql) not found. Database operations may fail."
    fi
    
    # Check Redis client
    if ! command_exists redis-cli; then
        print_warning "Redis client (redis-cli) not found. Redis operations may fail."
    fi
    
    print_success "System dependencies installed"
}

# Install Python dependencies
install_python_dependencies() {
    print_step "Installing Python dependencies"
    
    # Navigate to backend directory
    cd backend
    
    # Create virtual environment if it doesn't exist
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed from requirements.txt"
    else
        print_warning "requirements.txt not found, installing minimal dependencies"
        pip install fastapi uvicorn sqlalchemy asyncpg redis pydantic pydantic-settings structlog
    fi
    
    # Install additional RASP dependencies
    pip install aiohttp asyncio-mqtt prometheus-client psutil
    print_success "RASP-specific dependencies installed"
    
    # Deactivate virtual environment
    deactivate
    
    cd ..
}

# Initialize database
initialize_database() {
    print_step "Initializing database"
    
    # Test database connection
    if test_database_connection $DATABASE_HOST $DATABASE_PORT $DATABASE_NAME $DATABASE_USER $DATABASE_PASSWORD; then
        print_success "Database connection successful"
    else
        print_error "Cannot connect to database. Please check your database configuration."
        exit 1
    fi
    
    # Run database initialization script
    if [[ -f "scripts/init-rasp-db.sql" ]]; then
        print_step "Running RASP database initialization script"
        
        export PGPASSWORD=$DATABASE_PASSWORD
        psql -h $DATABASE_HOST -p $DATABASE_PORT -U $DATABASE_USER -d $DATABASE_NAME -f scripts/init-rasp-db.sql
        
        if [[ $? -eq 0 ]]; then
            print_success "RASP database schema initialized successfully"
        else
            print_error "Failed to initialize RASP database schema"
            exit 1
        fi
    else
        print_warning "RASP database initialization script not found"
    fi
    
    # Initialize database tables using Python
    print_step "Creating database tables"
    
    cd backend
    source venv/bin/activate
    
    python3 -c "
import asyncio
import sys
import os
sys.path.append('.')
from app.core.database import init_db
from app.models.rasp import Base
from app.core.config import settings

async def init():
    try:
        await init_db()
        print('Database tables created successfully')
    except Exception as e:
        print(f'Error creating tables: {e}')
        sys.exit(1)

asyncio.run(init())
"
    
    if [[ $? -eq 0 ]]; then
        print_success "Database tables created successfully"
    else
        print_error "Failed to create database tables"
        exit 1
    fi
    
    deactivate
    cd ..
}

# Test services
test_services() {
    print_step "Testing service connectivity"
    
    # Test database
    if test_port $DATABASE_HOST $DATABASE_PORT; then
        print_success "Database is accessible"
    else
        print_error "Database is not accessible"
        exit 1
    fi
    
    # Test Redis
    if test_port $REDIS_HOST $REDIS_PORT; then
        print_success "Redis is accessible"
    else
        print_warning "Redis is not accessible. Some features may not work properly."
    fi
    
    print_success "Service connectivity tests completed"
}

# Run test suite
run_test_suite() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        print_warning "Skipping test suite as requested"
        return
    fi
    
    print_step "Running RASP test suite"
    
    # Run the RASP test script
    python3 test-rasp.py
    
    if [[ $? -eq 0 ]]; then
        print_success "RASP test suite passed"
    else
        print_error "RASP test suite failed"
        exit 1
    fi
}

# Start backend
start_backend() {
    print_step "Starting RASP backend"
    
    cd backend
    
    if [[ "$USE_DOCKER" == "true" ]]; then
        # Use Docker deployment
        if command_exists docker; then
            print_step "Deploying with Docker"
            
            # Build Docker image
            docker build -t cybershield-rasp .
            
            # Run Docker container
            docker run -d \
                --name cybershield-rasp \
                -p $API_PORT:8000 \
                -e ENVIRONMENT=$ENVIRONMENT \
                -e DATABASE_HOST=$DATABASE_HOST \
                -e DATABASE_PORT=$DATABASE_PORT \
                -e DATABASE_NAME=$DATABASE_NAME \
                -e DATABASE_USER=$DATABASE_USER \
                -e DATABASE_PASSWORD=$DATABASE_PASSWORD \
                -e REDIS_HOST=$REDIS_HOST \
                -e REDIS_PORT=$REDIS_PORT \
                -e REDIS_PASSWORD=$REDIS_PASSWORD \
                cybershield-rasp
            
            print_success "RASP backend deployed with Docker"
        else
            print_error "Docker is not installed. Please install Docker or use native deployment."
            exit 1
        fi
    else
        # Native deployment
        print_step "Starting native RASP backend"
        
        # Activate virtual environment
        source venv/bin/activate
        
        # Start the application in background
        nohup python3 main.py > ../logs/rasp-backend.log 2>&1 &
        RASP_PID=$!
        
        # Save PID for later use
        echo $RASP_PID > ../logs/rasp-backend.pid
        
        # Wait for service to start
        sleep 5
        
        # Test if service is running
        if curl -f http://localhost:$API_PORT/health >/dev/null 2>&1; then
            print_success "RASP backend started successfully (PID: $RASP_PID)"
        else
            print_error "RASP backend health check failed"
            exit 1
        fi
        
        deactivate
    fi
    
    cd ..
}

# Show deployment information
show_deployment_info() {
    print_step "Deployment Information"
    
    echo -e "\n${CYAN}🎯 RASP Backend Deployment Summary:${NC}"
    print_info "Environment: $ENVIRONMENT"
    print_info "API URL: http://localhost:$API_PORT"
    print_info "API Documentation: http://localhost:$API_PORT/docs"
    print_info "Database: $DATABASE_HOST:$DATABASE_PORT/$DATABASE_NAME"
    print_info "Redis: $REDIS_HOST:$REDIS_PORT"
    
    echo -e "\n${CYAN}📋 Key RASP Endpoints:${NC}"
    print_info "GET  /api/rasp/agents - List RASP agents"
    print_info "POST /api/rasp/agents - Create new agent"
    print_info "GET  /api/rasp/attacks - List detected attacks"
    print_info "GET  /api/rasp/rules - List detection rules"
    print_info "GET  /api/rasp/dashboard/overview - Dashboard overview"
    print_info "POST /api/rasp/webhook - Webhook for integrations"
    
    echo -e "\n${CYAN}🔧 Next Steps:${NC}"
    print_info "1. Configure RASP agents for your applications"
    print_info "2. Set up detection rules based on your security requirements"
    print_info "3. Integrate with SIEM/SOAR systems"
    print_info "4. Monitor and tune based on real-world usage"
    
    echo -e "\n${CYAN}📚 Documentation:${NC}"
    print_info "RASP README: RASP_README.md"
    print_info "Implementation Document: RASP_IMPLEMENTATION_DOCUMENT.md"
    print_info "Test Script: test-rasp.py"
    
    if [[ "$USE_DOCKER" != "true" ]]; then
        echo -e "\n${CYAN}🛠️  Management Commands:${NC}"
        print_info "Stop backend: kill \$(cat logs/rasp-backend.pid)"
        print_info "View logs: tail -f logs/rasp-backend.log"
        print_info "Restart backend: ./deploy-rasp-backend.sh"
    fi
}

# Main deployment process
main() {
    echo -e "${CYAN}🚀 RASP Backend Deployment Script${NC}"
    print_info "Environment: $ENVIRONMENT"
    print_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    
    initialize_environment
    install_dependencies
    install_python_dependencies
    initialize_database
    test_services
    run_test_suite
    start_backend
    show_deployment_info
    
    echo -e "\n${GREEN}🎉 RASP Backend deployment completed successfully!${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --database-host)
            DATABASE_HOST="$2"
            shift 2
            ;;
        --database-port)
            DATABASE_PORT="$2"
            shift 2
            ;;
        --database-name)
            DATABASE_NAME="$2"
            shift 2
            ;;
        --database-user)
            DATABASE_USER="$2"
            shift 2
            ;;
        --database-password)
            DATABASE_PASSWORD="$2"
            shift 2
            ;;
        --redis-host)
            REDIS_HOST="$2"
            shift 2
            ;;
        --redis-port)
            REDIS_PORT="$2"
            shift 2
            ;;
        --redis-password)
            REDIS_PASSWORD="$2"
            shift 2
            ;;
        --api-port)
            API_PORT="$2"
            shift 2
            ;;
        --use-docker)
            USE_DOCKER=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --environment ENV        Deployment environment (development, staging, production)"
            echo "  --database-host HOST     PostgreSQL database host"
            echo "  --database-port PORT     PostgreSQL database port"
            echo "  --database-name NAME     PostgreSQL database name"
            echo "  --database-user USER     PostgreSQL database user"
            echo "  --database-password PASS PostgreSQL database password"
            echo "  --redis-host HOST        Redis host"
            echo "  --redis-port PORT        Redis port"
            echo "  --redis-password PASS    Redis password"
            echo "  --api-port PORT          API server port"
            echo "  --use-docker             Use Docker for deployment"
            echo "  --skip-tests             Skip running test suite"
            echo "  -h, --help               Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@" 