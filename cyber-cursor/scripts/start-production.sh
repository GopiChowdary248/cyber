#!/bin/bash

# CyberShield Production Startup Script
# This script starts the application in production mode without mobile components

set -e

echo "🚀 Starting CyberShield in Production Mode..."
echo "=============================================="

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

# Check if Docker is running
check_docker() {
    print_status "Checking Docker status..."
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Check if Docker Compose is available
check_docker_compose() {
    print_status "Checking Docker Compose..."
    if ! docker-compose --version > /dev/null 2>&1; then
        print_error "Docker Compose is not available. Please install Docker Compose and try again."
        exit 1
    fi
    print_success "Docker Compose is available"
}

# Stop any existing containers
stop_existing() {
    print_status "Stopping any existing containers..."
    docker-compose -f docker-compose.production-no-mobile.yml down --remove-orphans || true
    print_success "Existing containers stopped"
}

# Build and start services
start_services() {
    print_status "Building and starting production services..."
    
    # Build images
    print_status "Building backend image..."
    docker-compose -f docker-compose.production-no-mobile.yml build backend
    
    print_status "Building frontend image..."
    docker-compose -f docker-compose.production-no-mobile.yml build frontend
    
    # Start all services
    print_status "Starting all services..."
    docker-compose -f docker-compose.production-no-mobile.yml up -d
    
    print_success "All services started successfully"
}

# Wait for services to be healthy
wait_for_health() {
    print_status "Waiting for services to be healthy..."
    
    # Wait for PostgreSQL
    print_status "Waiting for PostgreSQL..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker exec cybershield-postgres pg_isready -U cybershield_user -d cybershield > /dev/null 2>&1; then
            print_success "PostgreSQL is healthy"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        print_error "PostgreSQL failed to become healthy within 60 seconds"
        exit 1
    fi
    
    # Wait for Redis
    print_status "Waiting for Redis..."
    timeout=30
    while [ $timeout -gt 0 ]; do
        if docker exec cybershield-redis redis-cli --raw incr ping > /dev/null 2>&1; then
            print_success "Redis is healthy"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        print_error "Redis failed to become healthy within 30 seconds"
        exit 1
    fi
    
    # Wait for Backend
    print_status "Waiting for Backend API..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -f http://localhost:8000/health > /dev/null 2>&1; then
            print_success "Backend API is healthy"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        print_error "Backend API failed to become healthy within 60 seconds"
        exit 1
    fi
    
    # Wait for Frontend
    print_status "Waiting for Frontend..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if curl -f http://localhost:3000 > /dev/null 2>&1; then
            print_success "Frontend is healthy"
            break
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    
    if [ $timeout -le 0 ]; then
        print_error "Frontend failed to become healthy within 60 seconds"
        exit 1
    fi
}

# Show service status
show_status() {
    print_status "Service Status:"
    echo "=================="
    docker-compose -f docker-compose.production-no-mobile.yml ps
    
    echo ""
    print_status "Service URLs:"
    echo "================"
    echo "Frontend: http://localhost:3000"
    echo "Backend API: http://localhost:8000"
    echo "Nginx Proxy: http://localhost:80"
    echo "PostgreSQL: localhost:5432"
    echo "Redis: localhost:6379"
    
    echo ""
    print_status "Container Logs:"
    echo "==================="
    echo "View logs with: docker-compose -f docker-compose.production-no-mobile.yml logs -f [service_name]"
    echo "Stop services with: docker-compose -f docker-compose.production-no-mobile.yml down"
}

# Main execution
main() {
    check_docker
    check_docker_compose
    stop_existing
    start_services
    wait_for_health
    show_status
    
    echo ""
    print_success "🎉 CyberShield is now running in production mode!"
    print_success "Access your application at: http://localhost"
}

# Run main function
main "$@"
