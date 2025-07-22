"""
Standardized Error Handling for Chronoflow
Provides consistent error responses and logging patterns
"""

from flask import jsonify, render_template, flash, request, session
import logging
import traceback
from functools import wraps
from constants import *

def get_logger():
    """Get the application logger"""
    return logging.getLogger('chronoflow')

class ChronoflowError(Exception):
    """Base exception class for Chronoflow-specific errors"""
    def __init__(self, message, error_code=None, status_code=HTTP_INTERNAL_SERVER_ERROR):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code

class ValidationError(ChronoflowError):
    """Exception for validation errors"""
    def __init__(self, message, field=None):
        super().__init__(message, error_code='VALIDATION_ERROR', status_code=HTTP_BAD_REQUEST)
        self.field = field

class AuthenticationError(ChronoflowError):
    """Exception for authentication errors"""
    def __init__(self, message='Authentication failed'):
        super().__init__(message, error_code='AUTH_ERROR', status_code=HTTP_UNAUTHORIZED)

class AuthorizationError(ChronoflowError):
    """Exception for authorization errors"""
    def __init__(self, message='Access denied'):
        super().__init__(message, error_code='AUTHZ_ERROR', status_code=HTTP_FORBIDDEN)

class DatabaseError(ChronoflowError):
    """Exception for database operation errors"""
    def __init__(self, message='Database operation failed'):
        super().__init__(message, error_code='DB_ERROR', status_code=HTTP_INTERNAL_SERVER_ERROR)

class FileProcessingError(ChronoflowError):
    """Exception for file processing errors"""
    def __init__(self, message='File processing failed'):
        super().__init__(message, error_code='FILE_ERROR', status_code=HTTP_BAD_REQUEST)

def log_error_with_context(error, endpoint, user_id=None, additional_info=None):
    """Log error with standardized context information"""
    logger = get_logger()
    
    error_details = {
        'endpoint': endpoint,
        'user_id': user_id or session.get('user_id', 'anonymous'),
        'error_type': type(error).__name__,
        'error_message': str(error),
        'additional_info': additional_info,
        'request_method': getattr(request, 'method', None),
        'request_path': getattr(request, 'path', None),
        'user_agent': request.headers.get('User-Agent') if request else None,
        'ip_address': request.remote_addr if request else None
    }
    
    logger.error(f"Application Error: {error_details}")
    
    # Log full stack trace at debug level
    if hasattr(error, '__traceback__'):
        logger.debug(f"Stack trace: {traceback.format_exc()}")

def handle_api_error(error, endpoint=None, user_id=None, additional_info=None):
    """Handle API errors with consistent JSON responses"""
    # Log the error with context
    log_error_with_context(error, endpoint or request.endpoint, user_id, additional_info)
    
    # Return appropriate error response
    if isinstance(error, ChronoflowError):
        return jsonify({
            'success': False,
            'error': error.message,
            'error_code': error.error_code
        }), error.status_code
    else:
        # Generic error response for unexpected errors
        return jsonify({
            'success': False,
            'error': 'An internal error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), HTTP_INTERNAL_SERVER_ERROR

def handle_form_error(error, template_name, template_kwargs=None, endpoint=None, user_id=None, additional_info=None):
    """Handle form errors with consistent flash messages and template rendering"""
    # Log the error with context
    log_error_with_context(error, endpoint or request.endpoint, user_id, additional_info)
    
    # Add flash message for user feedback
    if isinstance(error, ChronoflowError):
        flash(error.message, 'error')
    else:
        flash('An unexpected error occurred. Please try again.', 'error')
    
    # Render template with error state
    template_kwargs = template_kwargs or {}
    return render_template(template_name, **template_kwargs)

def api_error_handler(endpoint=None):
    """Decorator for consistent API error handling"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ChronoflowError as e:
                return handle_api_error(e, endpoint or func.__name__)
            except Exception as e:
                return handle_api_error(e, endpoint or func.__name__)
        return wrapper
    return decorator

def form_error_handler(template_name, template_kwargs=None, endpoint=None):
    """Decorator for consistent form error handling"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ChronoflowError as e:
                return handle_form_error(e, template_name, template_kwargs, endpoint or func.__name__)
            except Exception as e:
                return handle_form_error(e, template_name, template_kwargs, endpoint or func.__name__)
        return wrapper
    return decorator

def validate_required_fields(data, required_fields):
    """Validate that all required fields are present and not empty"""
    missing_fields = []
    empty_fields = []
    
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
        elif not data[field] or str(data[field]).strip() == '':
            empty_fields.append(field)
    
    if missing_fields:
        raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")
    
    if empty_fields:
        raise ValidationError(f"Empty required fields: {', '.join(empty_fields)}")

def validate_request_data(data, schema):
    """Validate request data against a schema
    
    Schema format:
    {
        'field_name': {
            'required': True/False,
            'type': str/int/float/bool,
            'validator': function,
            'max_length': int,
            'min_length': int
        }
    }
    """
    errors = []
    
    # Check required fields
    required_fields = [k for k, v in schema.items() if v.get('required', False)]
    try:
        validate_required_fields(data, required_fields)
    except ValidationError as e:
        errors.append(str(e))
    
    # Validate each field
    for field_name, field_config in schema.items():
        if field_name not in data:
            continue
            
        value = data[field_name]
        
        # Type validation
        expected_type = field_config.get('type')
        if expected_type and not isinstance(value, expected_type):
            errors.append(f"{field_name} must be of type {expected_type.__name__}")
            continue
        
        # Length validation for strings
        if isinstance(value, str):
            max_length = field_config.get('max_length')
            min_length = field_config.get('min_length')
            
            if max_length and len(value) > max_length:
                errors.append(f"{field_name} exceeds maximum length of {max_length}")
            
            if min_length and len(value) < min_length:
                errors.append(f"{field_name} is below minimum length of {min_length}")
        
        # Custom validator
        validator = field_config.get('validator')
        if validator and callable(validator):
            try:
                if not validator(value):
                    errors.append(f"{field_name} is invalid")
            except Exception as e:
                errors.append(f"{field_name} validation failed: {str(e)}")
    
    if errors:
        raise ValidationError('; '.join(errors))

def safe_database_operation(operation, *args, **kwargs):
    """Wrapper for safe database operations with consistent error handling"""
    try:
        return operation(*args, **kwargs)
    except Exception as e:
        logger = get_logger()
        logger.error(f"Database operation failed: {str(e)}")
        logger.debug(f"Stack trace: {traceback.format_exc()}")
        raise DatabaseError(f"Database operation failed: {str(e)}")

def create_success_response(message=None, data=None):
    """Create a standardized success response"""
    response = {'success': True}
    if message:
        response['message'] = message
    if data:
        response['data'] = data
    return jsonify(response)

def create_error_response(message, error_code=None, status_code=HTTP_BAD_REQUEST):
    """Create a standardized error response"""
    response = {
        'success': False,
        'error': message
    }
    if error_code:
        response['error_code'] = error_code
    
    return jsonify(response), status_code