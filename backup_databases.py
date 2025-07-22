#!/usr/bin/env python3
"""
Chronoflow Database Backup Tool
Backs up all user databases before upgrading Chronoflow

Usage:
    python backup_databases.py [--backup-dir /path/to/backups]
    python backup_databases.py --restore /path/to/backup --user-id USER_ID
"""

import os
import sys
import shutil
import sqlite3
import json
import argparse
from datetime import datetime
from pathlib import Path

# Constants
DEFAULT_BACKUP_DIR = 'chronoflow_backups'
MAIN_DB_FILE = 'main.db'
CONFIG_FILE = 'config.json'
USER_DB_FOLDER = 'user_databases'

class ChronoflowBackup:
    """Handle database backups for Chronoflow"""
    
    def __init__(self, backup_dir=DEFAULT_BACKUP_DIR):
        self.backup_dir = Path(backup_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_path = self.backup_dir / f"chronoflow_backup_{self.timestamp}"
        
    def create_backup(self):
        """Create a complete backup of all Chronoflow databases and configuration"""
        try:
            print(f"Creating backup at: {self.backup_path}")
            
            # Create backup directory
            self.backup_path.mkdir(parents=True, exist_ok=True)
            
            # Backup main database
            if self._backup_main_database():
                print("✓ Main database backed up successfully")
            else:
                print("✗ Failed to backup main database")
                return False
            
            # Backup user databases
            user_count = self._backup_user_databases()
            if user_count >= 0:
                print(f"✓ {user_count} user databases backed up successfully")
            else:
                print("✗ Failed to backup user databases")
                return False
            
            # Backup configuration
            if self._backup_configuration():
                print("✓ Configuration backed up successfully")
            else:
                print("⚠ Configuration backup failed (non-critical)")
            
            # Create backup manifest
            self._create_backup_manifest(user_count)
            
            print(f"\nBackup completed successfully!")
            print(f"Backup location: {self.backup_path}")
            print(f"To restore, use: python {sys.argv[0]} --restore {self.backup_path}")
            
            return True
            
        except Exception as e:
            print(f"Backup failed: {e}")
            return False
    
    def _backup_main_database(self):
        """Backup the main database file"""
        try:
            if os.path.exists(MAIN_DB_FILE):
                # Verify database integrity before backup
                if not self._verify_database_integrity(MAIN_DB_FILE):
                    print(f"Warning: Main database integrity check failed")
                
                shutil.copy2(MAIN_DB_FILE, self.backup_path / MAIN_DB_FILE)
                return True
            else:
                print(f"Warning: Main database file not found: {MAIN_DB_FILE}")
                return False
        except Exception as e:
            print(f"Error backing up main database: {e}")
            return False
    
    def _backup_user_databases(self):
        """Backup all user databases"""
        try:
            user_db_path = Path(USER_DB_FOLDER)
            backup_user_db_path = self.backup_path / USER_DB_FOLDER
            
            if not user_db_path.exists():
                print(f"User database folder not found: {USER_DB_FOLDER}")
                return 0
            
            backup_user_db_path.mkdir(exist_ok=True)
            user_count = 0
            
            for db_file in user_db_path.glob("*.db"):
                try:
                    # Verify database integrity before backup
                    if not self._verify_database_integrity(db_file):
                        print(f"Warning: Database integrity check failed for {db_file.name}")
                    
                    shutil.copy2(db_file, backup_user_db_path / db_file.name)
                    user_count += 1
                except Exception as e:
                    print(f"Error backing up user database {db_file.name}: {e}")
            
            return user_count
        except Exception as e:
            print(f"Error backing up user databases: {e}")
            return -1
    
    def _backup_configuration(self):
        """Backup configuration files"""
        try:
            if os.path.exists(CONFIG_FILE):
                shutil.copy2(CONFIG_FILE, self.backup_path / CONFIG_FILE)
            
            # Also backup VERSION and CHANGELOG if they exist
            for file in ['VERSION', 'CHANGELOG.md']:
                if os.path.exists(file):
                    shutil.copy2(file, self.backup_path / file)
            
            return True
        except Exception as e:
            print(f"Error backing up configuration: {e}")
            return False
    
    def _create_backup_manifest(self, user_count):
        """Create a manifest file with backup information"""
        manifest = {
            'backup_timestamp': self.timestamp,
            'backup_date': datetime.now().isoformat(),
            'chronoflow_version': self._get_chronoflow_version(),
            'main_database': os.path.exists(MAIN_DB_FILE),
            'user_database_count': user_count,
            'configuration_files': [
                f for f in [CONFIG_FILE, 'VERSION', 'CHANGELOG.md'] 
                if os.path.exists(f)
            ],
            'backup_script_version': '1.0.0'
        }
        
        with open(self.backup_path / 'backup_manifest.json', 'w') as f:
            json.dump(manifest, f, indent=2)
    
    def _get_chronoflow_version(self):
        """Get the current Chronoflow version"""
        try:
            if os.path.exists('VERSION'):
                with open('VERSION', 'r') as f:
                    return f.read().strip()
        except Exception:
            pass
        return 'unknown'
    
    def _verify_database_integrity(self, db_path):
        """Verify SQLite database integrity"""
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()
            conn.close()
            return result[0] == 'ok'
        except Exception:
            return False
    
    def restore_backup(self, backup_path, user_id=None):
        """Restore from a backup"""
        try:
            backup_path = Path(backup_path)
            
            if not backup_path.exists():
                print(f"Backup path does not exist: {backup_path}")
                return False
            
            # Load manifest
            manifest_path = backup_path / 'backup_manifest.json'
            if manifest_path.exists():
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                print(f"Restoring backup from: {manifest['backup_date']}")
                print(f"Original Chronoflow version: {manifest['chronoflow_version']}")
            else:
                print("Warning: Backup manifest not found")
            
            # Confirm restoration
            response = input("This will overwrite existing databases. Continue? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("Restoration cancelled")
                return False
            
            # Restore main database
            main_db_backup = backup_path / MAIN_DB_FILE
            if main_db_backup.exists():
                shutil.copy2(main_db_backup, MAIN_DB_FILE)
                print("✓ Main database restored")
            
            # Restore user databases
            user_db_backup_path = backup_path / USER_DB_FOLDER
            if user_db_backup_path.exists():
                if user_id:
                    # Restore specific user database
                    user_db_file = f"{user_id}.db"
                    source = user_db_backup_path / user_db_file
                    dest = Path(USER_DB_FOLDER) / user_db_file
                    if source.exists():
                        dest.parent.mkdir(exist_ok=True)
                        shutil.copy2(source, dest)
                        print(f"✓ User database {user_id} restored")
                    else:
                        print(f"✗ User database {user_id} not found in backup")
                        return False
                else:
                    # Restore all user databases
                    if os.path.exists(USER_DB_FOLDER):
                        shutil.rmtree(USER_DB_FOLDER)
                    shutil.copytree(user_db_backup_path, USER_DB_FOLDER)
                    print("✓ All user databases restored")
            
            # Restore configuration
            config_backup = backup_path / CONFIG_FILE
            if config_backup.exists():
                shutil.copy2(config_backup, CONFIG_FILE)
                print("✓ Configuration restored")
            
            print("\nRestore completed successfully!")
            return True
            
        except Exception as e:
            print(f"Restore failed: {e}")
            return False
    
    def list_backups(self):
        """List available backups"""
        try:
            if not self.backup_dir.exists():
                print(f"Backup directory does not exist: {self.backup_dir}")
                return
            
            backups = []
            for backup in self.backup_dir.glob("chronoflow_backup_*"):
                if backup.is_dir():
                    manifest_path = backup / 'backup_manifest.json'
                    if manifest_path.exists():
                        try:
                            with open(manifest_path, 'r') as f:
                                manifest = json.load(f)
                            backups.append({
                                'path': backup,
                                'date': manifest['backup_date'],
                                'version': manifest['chronoflow_version'],
                                'user_count': manifest['user_database_count']
                            })
                        except Exception:
                            backups.append({
                                'path': backup,
                                'date': 'unknown',
                                'version': 'unknown',
                                'user_count': 'unknown'
                            })
            
            if not backups:
                print("No backups found")
                return
            
            print(f"Available backups in {self.backup_dir}:")
            print("-" * 80)
            for backup in sorted(backups, key=lambda x: x['date'], reverse=True):
                print(f"Path: {backup['path'].name}")
                print(f"Date: {backup['date']}")
                print(f"Version: {backup['version']}")
                print(f"Users: {backup['user_count']}")
                print("-" * 80)
                
        except Exception as e:
            print(f"Error listing backups: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Chronoflow Database Backup Tool')
    parser.add_argument('--backup-dir', default=DEFAULT_BACKUP_DIR,
                      help=f'Backup directory (default: {DEFAULT_BACKUP_DIR})')
    parser.add_argument('--restore', metavar='BACKUP_PATH',
                      help='Restore from backup path')
    parser.add_argument('--user-id', metavar='USER_ID',
                      help='Restore specific user database only')
    parser.add_argument('--list', action='store_true',
                      help='List available backups')
    
    args = parser.parse_args()
    
    backup_tool = ChronoflowBackup(args.backup_dir)
    
    if args.list:
        backup_tool.list_backups()
    elif args.restore:
        success = backup_tool.restore_backup(args.restore, args.user_id)
        sys.exit(0 if success else 1)
    else:
        # Default action: create backup
        success = backup_tool.create_backup()
        sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()