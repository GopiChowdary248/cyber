#!/bin/bash

# CyberShield Production Database Automated Backup Script
# This script implements a comprehensive backup strategy

set -e

# Configuration
DB_NAME="cybershield"
DB_USER="cybershield_user"
DB_PASSWORD="cybershield_password"
DB_HOST="localhost"
DB_PORT="5432"
BACKUP_DIR="/var/lib/postgresql/backups"
ARCHIVE_DIR="/var/lib/postgresql/archive"
RETENTION_DAYS=30
RETENTION_WEEKS=4
RETENTION_MONTHS=12

# Create backup directories if they don't exist
mkdir -p "$BACKUP_DIR"
mkdir -p "$ARCHIVE_DIR"

# Timestamp for backup files
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DATE=$(date +"%Y%m%d")
WEEK=$(date +"%Y%W")
MONTH=$(date +"%Y%m")

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$BACKUP_DIR/backup.log"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Function to perform full database backup
perform_full_backup() {
    local backup_file="$BACKUP_DIR/full_backup_${TIMESTAMP}.sql"
    local compressed_file="${backup_file}.gz"
    
    log "Starting full database backup..."
    
    # Perform pg_dump with compression
    PGPASSWORD="$DB_PASSWORD" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --clean \
        --create \
        --if-exists \
        --no-password \
        --format=custom \
        --compress=9 \
        --file="$compressed_file" \
        || error_exit "Full backup failed"
    
    log "Full backup completed: $compressed_file"
    
    # Create checksum for verification
    sha256sum "$compressed_file" > "${compressed_file}.sha256"
    
    # Verify backup integrity
    verify_backup "$compressed_file"
}

# Function to perform incremental backup (WAL archiving)
perform_incremental_backup() {
    log "Starting incremental backup (WAL archiving)..."
    
    # Check if WAL archiving is working
    local current_wal=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_current_wal_lsn();" | tr -d ' ')
    
    if [ -n "$current_wal" ]; then
        log "Current WAL position: $current_wal"
        
        # Archive current WAL file
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT pg_switch_wal();"
        
        log "WAL archiving completed"
    else
        error_exit "Failed to get WAL position"
    fi
}

# Function to verify backup integrity
verify_backup() {
    local backup_file="$1"
    local checksum_file="${backup_file}.sha256"
    
    log "Verifying backup integrity..."
    
    if [ -f "$checksum_file" ]; then
        if sha256sum -c "$checksum_file"; then
            log "Backup verification successful"
        else
            error_exit "Backup verification failed"
        fi
    else
        error_exit "Checksum file not found"
    fi
}

# Function to perform backup rotation
rotate_backups() {
    log "Starting backup rotation..."
    
    # Remove old daily backups
    find "$BACKUP_DIR" -name "full_backup_*.sql.gz" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "full_backup_*.sql.gz.sha256" -mtime +$RETENTION_DAYS -delete
    
    # Remove old weekly backups
    find "$BACKUP_DIR" -name "weekly_backup_*.sql.gz" -mtime +$((RETENTION_WEEKS * 7)) -delete
    find "$BACKUP_DIR" -name "weekly_backup_*.sql.gz.sha256" -mtime +$((RETENTION_WEEKS * 7)) -delete
    
    # Remove old monthly backups
    find "$BACKUP_DIR" -name "monthly_backup_*.sql.gz" -mtime +$((RETENTION_MONTHS * 30)) -delete
    find "$BACKUP_DIR" -name "monthly_backup_*.sql.gz.sha256" -mtime +$((RETENTION_MONTHS * 30)) -delete
    
    # Remove old WAL archives
    find "$ARCHIVE_DIR" -name "*.wal" -mtime +$RETENTION_DAYS -delete
    
    log "Backup rotation completed"
}

# Function to create weekly backup
create_weekly_backup() {
    local day_of_week=$(date +%u)
    
    # Create weekly backup on Sunday (day 7)
    if [ "$day_of_week" -eq 7 ]; then
        local weekly_file="$BACKUP_DIR/weekly_backup_${WEEK}.sql.gz"
        local compressed_file="$BACKUP_DIR/full_backup_${TIMESTAMP}.sql.gz"
        
        log "Creating weekly backup..."
        cp "$compressed_file" "$weekly_file"
        cp "${compressed_file}.sha256" "${weekly_file}.sha256"
        log "Weekly backup created: $weekly_file"
    fi
}

# Function to create monthly backup
create_monthly_backup() {
    local day_of_month=$(date +%d)
    
    # Create monthly backup on the 1st of each month
    if [ "$day_of_month" -eq 01 ]; then
        local monthly_file="$BACKUP_DIR/monthly_backup_${MONTH}.sql.gz"
        local compressed_file="$BACKUP_DIR/full_backup_${TIMESTAMP}.sql.gz"
        
        log "Creating monthly backup..."
        cp "$compressed_file" "$monthly_file"
        cp "${compressed_file}.sha256" "${monthly_file}.sha256"
        log "Monthly backup created: $month_file"
    fi
}

# Function to check disk space
check_disk_space() {
    local backup_dir_usage=$(df "$BACKUP_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
    local archive_dir_usage=$(df "$ARCHIVE_DIR" | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$backup_dir_usage" -gt 80 ] || [ "$archive_dir_usage" -gt 80 ]; then
        log "WARNING: Disk space usage is high (Backup: ${backup_dir_usage}%, Archive: ${archive_dir_usage}%)"
        
        # Trigger more aggressive cleanup
        find "$BACKUP_DIR" -name "*.sql.gz" -mtime +7 -delete
        find "$BACKUP_DIR" -name "*.sha256" -mtime +7 -delete
        find "$ARCHIVE_DIR" -name "*.wal" -mtime +7 -delete
        
        log "Emergency cleanup completed"
    fi
}

# Function to send backup status notification
send_notification() {
    local status="$1"
    local message="$2"
    
    # Log the notification
    log "NOTIFICATION: $status - $message"
    
    # Here you can add email, Slack, or other notification methods
    # Example: curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$message\"}" $SLACK_WEBHOOK_URL
}

# Function to test backup restoration
test_backup_restoration() {
    local test_db="cybershield_test_restore"
    local backup_file="$1"
    
    log "Testing backup restoration..."
    
    # Create test database
    PGPASSWORD="$DB_PASSWORD" createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$test_db" || {
        log "WARNING: Could not create test database for restoration test"
        return 1
    }
    
    # Restore backup to test database
    PGPASSWORD="$DB_PASSWORD" pg_restore \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$test_db" \
        --clean \
        --if-exists \
        --no-password \
        "$backup_file" || {
        log "WARNING: Backup restoration test failed"
        PGPASSWORD="$DB_PASSWORD" dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$test_db"
        return 1
    }
    
    # Drop test database
    PGPASSWORD="$DB_PASSWORD" dropdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$test_db"
    
    log "Backup restoration test successful"
    return 0
}

# Main backup execution
main() {
    log "=== Starting CyberShield Database Backup Process ==="
    
    # Check disk space before starting
    check_disk_space
    
    # Perform full backup
    perform_full_backup
    
    # Perform incremental backup
    perform_incremental_backup
    
    # Create weekly and monthly backups if needed
    create_weekly_backup
    create_monthly_backup
    
    # Rotate old backups
    rotate_backups
    
    # Test backup restoration (optional, can be disabled for large databases)
    # test_backup_restoration "$compressed_file"
    
    # Final disk space check
    check_disk_space
    
    log "=== Backup Process Completed Successfully ==="
    
    # Send success notification
    send_notification "SUCCESS" "Database backup completed successfully at $(date)"
}

# Execute main function
main "$@"
