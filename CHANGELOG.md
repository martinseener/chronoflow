# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.1] - 2025-07-22

### Critical Bug Fixes
- Corrected session key mismatch where `complete_login_session()` set `login_time` but `login_required` expected `last_activity`
- Fixed type handling in session timeout checks preventing `fromisoformat` errors
- Added robust error handling for invalid session timestamps
- Updated critical API endpoints to use `get_user_db()` context managers:
  - `get_projects()` - Fixes project loading issues
  - `get_time_entries()` - Fixes time entries display
  - `create_project()` - Fixes project creation
  - `update_project()` - Fixes project editing
  - `archive_project()` and `unarchive_project()` - Fixes project archiving
- Ensures proper transaction management and connection cleanup
- Fixed "fromisoformat: argument must be str" errors causing 500 responses

## [1.4.0] - 2025-07-21

### Major Code Quality & Architecture Enhancements
- **Advanced Function Refactoring**
  - Refactored `register()` function (80 lines) into focused helper functions:
    - `validate_registration_data()` - Comprehensive form validation
    - `check_user_exists()` - Database user existence check
    - `create_new_user()` - Secure user creation with UUID and TOTP
    - `setup_new_user_session()` - Session initialization
  - Separated `export_data()` function into format-specific handlers:
    - `build_export_query()` - Dynamic query construction with filters
    - `fetch_export_data()` - Data retrieval with database context management
    - `handle_csv_export()` - CSV format export processing
    - `handle_json_export()` - JSON format export processing
    - `handle_full_backup_export()` - Complete backup functionality

### Standardized Error Handling System
- **Created comprehensive error handling framework (`error_handlers.py`)**
  - Custom exception classes for different error types:
    - `ValidationError` - Input validation failures
    - `AuthenticationError` - Authentication failures  
    - `AuthorizationError` - Authorization failures
    - `DatabaseError` - Database operation errors
    - `FileProcessingError` - File processing errors
  - Standardized error response patterns for API and form endpoints
  - Consistent logging with contextual information (user_id, endpoint, request details)
  - Error handling decorators for automatic exception processing

### Database Backup & Recovery System
- **Created professional database backup tools**
  - **Python backup script (`backup_databases.py`)**:
    - Complete backup of main database and all user databases
    - Database integrity verification before backup
    - Backup manifest with metadata and version information
    - Individual user database restore capability
    - Comprehensive backup listing and management
  - **Bash wrapper script (`backup_databases.sh`)**:
    - User-friendly command-line interface
    - Automatic Chronoflow process detection and management
    - Color-coded status output and error handling
    - Pre-upgrade backup automation support

### Enhanced Documentation & Code Quality
- **Comprehensive docstring documentation**
  - Added detailed docstrings to all major functions
  - Included parameter types, return values, and usage examples
  - Security considerations and implementation notes
  - Cross-reference documentation for complex workflows
- **Improved code maintainability**
  - Better separation of concerns across all refactored functions
  - Reduced function complexity and improved readability
  - Enhanced error handling consistency across the application

### Developer & Operations Experience
- **Simplified backup/restore workflows** for system administrators
- **Enhanced debugging capabilities** with structured error logging
- **Improved code navigation** through better function organization
- **Reduced maintenance overhead** through standardized patterns

### Security Enhancements
- **Maintained security-first approach** in all refactored code
- **Preserved timing attack protections** in authentication flows
- **Enhanced database operation safety** with transaction management
- **Improved error information disclosure controls**

## [1.3.0] - 2025-07-21

### Code Quality & Refactoring
- **Database Connection Management**
  - Added database connection context managers (`get_main_db()`, `get_user_db()`)
  - Automatic connection cleanup and transaction rollback on errors
  - Eliminated 30+ repetitive database connection patterns throughout codebase
- **Function Decomposition for Maintainability**
  - Broke down `import_data()` function (138 lines) into focused helper functions:
    - `validate_and_parse_import_file()` - File validation and parsing
    - `import_projects_data()` - Project import handling
    - `import_time_entries_data()` - Time entries import handling
  - Refactored `login()` function (106 lines) into specialized helper functions:
    - `authenticate_user_credentials()` - User authentication
    - `handle_backup_code_login()` - Backup code processing
    - `handle_totp_verification()` - TOTP verification
    - `complete_login_session()` - Session setup
    - `apply_timing_protection()` - Timing attack prevention
- **Constants and Code Organization**
  - Created comprehensive `constants.py` file with 50+ application constants
  - Eliminated magic numbers and hardcoded strings throughout the application
  - Standardized file size limits, timing delays, string lengths, and error messages
  - Improved code maintainability and consistency

## [1.2.4] - 2025-07-21

### Security
- Enhanced session security management
  - Added configurable session timeout with default 24-hour expiration
  - Implemented secure cookie flags (HTTPOnly, Secure, SameSite) with configuration options
  - Added automatic session invalidation on password changes with user notification
  - Session timeout checks integrated into login_required decorator
- Implemented comprehensive per-user rate limiting for sensitive operations
  - Enhanced rate limiting for 2FA operations (setup, verify, disable) - 10 per hour per user
  - Password change rate limiting - 3 attempts per hour per user
  - Data export rate limiting - 20 requests per hour per user  
  - Data import rate limiting - 5 requests per hour per user
  - User-based rate limiting keys prevent IP-based bypass attacks

## [1.2.3] - 2025-07-21

### Security
- Enhanced file upload security with comprehensive validation pipeline
  - Added file size limits (10MB maximum)
  - Implemented MIME type validation for uploads
  - Added JSON structure validation for import files
  - Enhanced malicious file detection and prevention
- Fixed information disclosure vulnerabilities
  - Implemented generic error responses for production
  - Added detailed server-side error logging while hiding sensitive information from users
  - Generic error handlers prevent stack trace exposure
- Added production secret key warning system
  - Dashboard shows security warning when default secret key is used in production
  - Context-aware warning (only appears when debug=false)
  - Helps prevent accidental production deployment with weak keys

## [1.2.2] - 2025-07-21

### Security
- Fixed SQL injection vulnerabilities in query construction
  - Replaced f-string interpolation with safe string concatenation in billing status filters
  - Secured dynamic WHERE clause construction in get_time_entries() and export_data()
- Fixed debug mode exposure in production
  - Added flexible debug configuration via environment variable or config file

## [1.2.1] - 2025-07-21

### Security
- Fixed CSRF vulnerabilities across all API endpoints
  - Removed @csrf.exempt decorators from 17 API endpoints
  - Added CSRF token protection to all AJAX requests
  - Implemented secure fetch helpers with automatic CSRF token inclusion
  - Protected project management, time tracking, 2FA, and import/export operations

## [1.2.0] - 2025-07-21

### Security
- Fixed multiple XSS vulnerabilities in templates and JavaScript
- Added comprehensive input validation and sanitization
  - Email format validation with length limits
  - Password strength requirements (8+ chars, letters + numbers)
  - Project names filtered for XSS characters with length limits
  - API endpoints now validate all input data with detailed error messages
- Enhanced authentication security with proper input validation on all forms

## [1.1.3] - 2025-07-21

### Bugfixes
- Fix timezone conversions for "Manual Entry" tracking

## [1.1.2] - 2025-07-06

### Bugfixes
- Fix remaining timezone bug leftover in the edit modal

## [1.1.1] - 2025-07-06

### Bugfixes
- Fixed earnings calculation precision errors that caused totals to be off by 1 cent
  - Earnings calculations now properly round to 2 decimal places

## [1.1.0] - 2025-07-05

### Added
- Footer with version display at the bottom of the dashboard
- Separate earnings breakdown in time history summary:
  - Open Earnings: Shows earnings from pending entries
  - Invoiced Earnings: Shows earnings from invoiced entries
  - Total Earnings: Shows combined earnings (unchanged)

## [1.0.1] - 2025-07-05

### Bugfixes
- CSV/JSON exports now use local timezone instead of UTC time
- Unbilled entries earnings now set to 0 and removed from total earnings calculation (reversable)
- Add password confirmation field for registrations to minimize risk of typos

## [1.0.0] - 2025-07-03

### Added
- Released v1.0.0 of Chronoflow to the public
