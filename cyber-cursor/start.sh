#!/bin/bash

# CyberShield Containerized Application Startup Script
# This script helps you start the full-stack application with Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to check if Docker Compose is available
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
    print_success "Docker Compose is available"
}

# Function to check if .env file exists
check_env_file() {
    if [ ! -f ".env" ]; then
        print_warning ".env file not found. Creating from template..."
        if [ -f "env.example" ]; then
            cp env.example .env
            print_success "Created .env file from template"
            print_warning "Please review and update the .env file with your configuration"
        else
            print_error "env.example file not found. Please create a .env file manually."
            exit 1
        fi
    else
        print_success ".env file found"
    fi
}

# Function to check available ports
check_ports() {
    local ports=("80" "3000" "5432" "6379" "8000")
    local conflicts=()
    
    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            conflicts+=("$port")
        fi
    done
    
    if [ ${#conflicts[@]} -gt 0 ]; then
        print_warning "Port conflicts detected: ${conflicts[*]}"
        print_warning "Some services may not start properly. Please free up these ports or modify docker-compose.yml"
    else
        print_success "All required ports are available"
    fi
}

# Function to start services
start_services() {
    local profile=""
    
    if [ "$1" = "production" ]; then
        profile="--profile production"
        print_status "Starting services in production mode..."
    else
        print_status "Starting services in development mode..."
    fi
    
    # Build and start services
    docker-compose $profile up --build -d
    
    if [ $? -eq 0 ]; then
        print_success "Services started successfully"
    else
        print_error "Failed to start services"
        exit 1
    fi
}

# Function to wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    # Wait for database
    print_status "Waiting for PostgreSQL..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker-compose exec -T postgres pg_isready -U cybershield_user > /dev/null 2>&1; then
            print_success "PostgreSQL is ready"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        print_warning "PostgreSQL may not be fully ready"
    fi
    
    # Wait for backend
    print_status "Waiting for backend API..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -f http://localhost:8000/health > /dev/null 2>&1; then
            print_success "Backend API is ready"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        print_warning "Backend API may not be fully ready"
    fi
}

# Function to show service status
show_status() {
    print_status "Service Status:"
    docker-compose ps
    
    echo ""
    print_status "Application URLs:"
    echo -e "  ${GREEN}Frontend:${NC} http://localhost:3000"
    echo -e "  ${GREEN}Backend API:${NC} http://localhost:8000"
    echo -e "  ${GREEN}API Documentation:${NC} http://localhost:8000/docs"
    echo -e "  ${GREEN}Health Check:${NC} http://localhost:8000/health"
    
    if [ "$1" = "production" ]; then
        echo -e "  ${GREEN}Nginx (HTTP):${NC} http://localhost:80"
        echo -e "  ${GREEN}Nginx (HTTPS):${NC} https://localhost:443"
    fi
}

# Function to show logs
show_logs() {
    print_status "Recent logs (last 20 lines):"
    docker-compose logs --tail=20
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."
    docker-compose down
    print_success "Services stopped"
}

# Function to restart services
restart_services() {
    print_status "Restarting services..."
    docker-compose restart
    print_success "Services restarted"
}

# Function to clean up
cleanup() {
    print_status "Cleaning up containers and volumes..."
    docker-compose down --volumes --remove-orphans
    print_success "Cleanup completed"
}

# Function to show help
show_help() {
    echo "CyberShield Containerized Application Startup Script"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start              Start services in development mode"
    echo "  start-production   Start services in production mode (with Nginx, Celery)"
    echo "  stop               Stop all services"
    echo "  restart            Restart all services"
    echo "  status             Show service status and URLs"
    echo "  logs               Show recent logs"
    echo "  cleanup            Stop and remove all containers and volumes"
    echo "  help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start           # Start in development mode"
    echo "  $0 start-production # Start in production mode"
    echo "  $0 status          # Check service status"
}

# Main script logic
case "${1:-start}" in
    "start")
        print_status "Starting CyberShield application..."
        check_docker
        check_docker_compose
        check_env_file
        check_ports
        start_services
        wait_for_services
        show_status
        show_logs
        ;;
    "start-production")
        print_status "Starting CyberShield application in production mode..."
        check_docker
        check_docker_compose
        check_env_file
        check_ports
        start_services production
        wait_for_services
        show_status production
        show_logs
        ;;
    "stop")
        stop_services
        ;;
    "restart")
        restart_services
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs
        ;;
    "cleanup")
        cleanup
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac 