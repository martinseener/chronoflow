#!/bin/bash

# Chronoflow Database Backup Script
# Simple bash wrapper for the Python backup tool

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default settings
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_TOOL="$SCRIPT_DIR/backup_databases.py"
DEFAULT_BACKUP_DIR="chronoflow_backups"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}"
    echo "========================================="
    echo "    Chronoflow Database Backup Tool"
    echo "========================================="
    echo -e "${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    # Check if we're in the Chronoflow directory
    if [[ ! -f "app.py" ]]; then
        print_error "This script must be run from the Chronoflow root directory"
        exit 1
    fi
    
    # Check if Python backup script exists
    if [[ ! -f "$BACKUP_TOOL" ]]; then
        print_error "Python backup tool not found: $BACKUP_TOOL"
        exit 1
    fi
    
    # Check Python availability
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi
}

# Function to display usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  backup                    Create a backup (default)"
    echo "  restore BACKUP_PATH       Restore from backup"
    echo "  list                      List available backups"
    echo ""
    echo "Options:"
    echo "  --backup-dir DIR          Backup directory (default: $DEFAULT_BACKUP_DIR)"
    echo "  --user-id USER_ID         Restore specific user only"
    echo "  --help                    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                        # Create a backup"
    echo "  $0 backup                 # Create a backup"
    echo "  $0 list                   # List available backups"
    echo "  $0 restore chronoflow_backups/chronoflow_backup_20250721_143020"
    echo "  $0 restore backup_path --user-id abc-123"
}

# Function to create backup
create_backup() {
    print_status "Starting database backup..."
    
    # Stop Chronoflow if it's running (optional)
    if pgrep -f "python.*app.py" > /dev/null; then
        print_warning "Chronoflow appears to be running. Consider stopping it first."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Backup cancelled"
            exit 0
        fi
    fi
    
    # Create backup using Python tool
    if python3 "$BACKUP_TOOL" "$@"; then
        print_status "Backup completed successfully!"
    else
        print_error "Backup failed!"
        exit 1
    fi
}

# Function to restore backup
restore_backup() {
    local backup_path="$1"
    shift
    
    if [[ -z "$backup_path" ]]; then
        print_error "Backup path is required for restore"
        usage
        exit 1
    fi
    
    print_warning "This will restore databases from: $backup_path"
    print_warning "Current databases will be overwritten!"
    
    # Stop Chronoflow if it's running
    if pgrep -f "python.*app.py" > /dev/null; then
        print_warning "Stopping Chronoflow..."
        pkill -f "python.*app.py" || true
        sleep 2
    fi
    
    # Restore using Python tool
    if python3 "$BACKUP_TOOL" --restore "$backup_path" "$@"; then
        print_status "Restore completed successfully!"
        print_status "You can now restart Chronoflow"
    else
        print_error "Restore failed!"
        exit 1
    fi
}

# Function to list backups
list_backups() {
    print_status "Listing available backups..."
    python3 "$BACKUP_TOOL" --list "$@"
}

# Main script
main() {
    print_header
    check_prerequisites
    
    case "${1:-backup}" in
        "backup")
            shift
            create_backup "$@"
            ;;
        "restore")
            shift
            restore_backup "$@"
            ;;
        "list")
            shift
            list_backups "$@"
            ;;
        "--help"|"-h"|"help")
            usage
            ;;
        *)
            print_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"