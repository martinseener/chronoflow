# Constants for Chronoflow Application
# This file contains all magic numbers and strings used throughout the application

# File Upload Limits
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB maximum file size for uploads

# Rate Limiting
MAX_HOURLY_RATE = 10000  # Maximum reasonable hourly rate limit

# Time and Duration
MAX_DURATION_MINUTES = 86400  # Maximum duration in minutes (24 hours)
DEFAULT_SESSION_TIMEOUT_HOURS = 24  # Default session timeout in hours
TIMING_ATTACK_DELAY_SECONDS = 0.5  # Delay for timing attack prevention

# String Lengths
MAX_EMAIL_LENGTH = 254  # Maximum email address length
MIN_PASSWORD_LENGTH = 8  # Minimum password length
MAX_PROJECT_NAME_LENGTH = 100  # Maximum project name length
MAX_DESCRIPTION_LENGTH = 1000  # Maximum description length
MAX_TOTP_CODE_LENGTH = 10  # Maximum TOTP code length
MAX_BACKUP_CODE_LENGTH = 20  # Maximum backup code length

# Database
DEFAULT_BACKUP_CODES_COUNT = 10  # Number of backup codes to generate

# Billing Status Options
BILLING_STATUS_PENDING = 'pending'
BILLING_STATUS_INVOICED = 'invoiced'
BILLING_STATUS_UNBILLED = 'unbilled'

# Billing Increment Options
BILLING_INCREMENT_MINUTE = 'minute'
BILLING_INCREMENT_QUARTER_HOUR = 'quarter-hour'
BILLING_INCREMENT_HALF_HOUR = 'half-hour'
BILLING_INCREMENT_HOUR = 'hour'

# File Extensions and MIME Types
ALLOWED_UPLOAD_EXTENSIONS = {'.json'}
ALLOWED_MIME_TYPES = {'application/json', 'text/plain'}

# Error Messages
ERROR_INVALID_CREDENTIALS = 'Invalid credentials'
ERROR_INVALID_EMAIL = 'Invalid email format'
ERROR_INVALID_PASSWORD = 'Invalid password format'
ERROR_FILE_TOO_LARGE = f'File size exceeds maximum limit of {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB'
ERROR_INVALID_FILE_TYPE = 'Invalid file type'
ERROR_NO_FILE_PROVIDED = 'No file provided'
ERROR_GENERIC_IMPORT_FAILED = 'Import failed. Please check your file format and try again.'
ERROR_GENERIC_DATABASE = 'Database operation failed'

# Success Messages
SUCCESS_IMPORT_COMPLETE = 'Data imported successfully'
SUCCESS_2FA_DISABLED = '2FA has been disabled. You must set up 2FA again.'
SUCCESS_2FA_SETUP = '2FA setup successful!'
SUCCESS_PASSWORD_CHANGED = 'Password changed successfully'

# HTTP Status Codes
HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_SERVER_ERROR = 500

# Configuration Keys
CONFIG_FLASK = 'flask'
CONFIG_REGISTRATION = 'registration'
CONFIG_SECURITY = 'security'
CONFIG_SESSION = 'session'
CONFIG_RATE_LIMITING = 'rate_limiting'
CONFIG_LOGGING = 'logging'