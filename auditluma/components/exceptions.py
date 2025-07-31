"""
Exception classes for the unified Haystack generator component.

This module defines a comprehensive hierarchy of exceptions that can occur
during the operation of the unified generator system.
"""

from typing import Any, Dict, Optional


class UnifiedGeneratorError(Exception):
    """
    Base exception class for all unified generator errors.
    
    This is the root exception that all other generator-specific
    exceptions inherit from.
    """
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize the exception.
        
        Args:
            message: Human-readable error message
            details: Additional error details for debugging
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self) -> str:
        """Return string representation of the exception."""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ConfigurationError(UnifiedGeneratorError):
    """
    Exception raised for configuration-related errors.
    
    This includes invalid configuration values, missing required
    configuration, or configuration validation failures.
    """
    
    def __init__(self, message: str, config_key: Optional[str] = None, 
                 config_value: Optional[Any] = None, **kwargs):
        """
        Initialize configuration error.
        
        Args:
            message: Error message
            config_key: The configuration key that caused the error
            config_value: The invalid configuration value
            **kwargs: Additional details
        """
        details = kwargs
        if config_key:
            details['config_key'] = config_key
        if config_value is not None:
            details['config_value'] = config_value
        
        super().__init__(message, details)
        self.config_key = config_key
        self.config_value = config_value


class ProviderError(UnifiedGeneratorError):
    """
    Exception raised for provider-related errors.
    
    This includes errors in provider detection, provider initialization,
    or provider-specific configuration issues.
    """
    
    def __init__(self, message: str, provider: Optional[str] = None, 
                 model: Optional[str] = None, **kwargs):
        """
        Initialize provider error.
        
        Args:
            message: Error message
            provider: The provider that caused the error
            model: The model that caused the error
            **kwargs: Additional details
        """
        details = kwargs
        if provider:
            details['provider'] = provider
        if model:
            details['model'] = model
        
        super().__init__(message, details)
        self.provider = provider
        self.model = model


class APIError(UnifiedGeneratorError):
    """
    Exception raised for API-related errors.
    
    This includes HTTP errors, authentication failures, rate limiting,
    and other API communication issues.
    """
    
    def __init__(self, message: str, status_code: Optional[int] = None,
                 response_body: Optional[str] = None, provider: Optional[str] = None,
                 **kwargs):
        """
        Initialize API error.
        
        Args:
            message: Error message
            status_code: HTTP status code if applicable
            response_body: Response body from the API
            provider: The provider that returned the error
            **kwargs: Additional details
        """
        details = kwargs
        if status_code:
            details['status_code'] = status_code
        if response_body:
            details['response_body'] = response_body
        if provider:
            details['provider'] = provider
        
        super().__init__(message, details)
        self.status_code = status_code
        self.response_body = response_body
        self.provider = provider


class AuthenticationError(APIError):
    """
    Exception raised for authentication-related errors.
    
    This includes invalid API keys, expired tokens, or insufficient
    permissions for the requested operation.
    """
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        """
        Initialize authentication error.
        
        Args:
            message: Error message
            **kwargs: Additional details passed to APIError
        """
        super().__init__(message, **kwargs)


class RateLimitError(APIError):
    """
    Exception raised when API rate limits are exceeded.
    
    This includes both request rate limits and token usage limits.
    """
    
    def __init__(self, message: str = "Rate limit exceeded", 
                 retry_after: Optional[int] = None, **kwargs):
        """
        Initialize rate limit error.
        
        Args:
            message: Error message
            retry_after: Seconds to wait before retrying
            **kwargs: Additional details passed to APIError
        """
        if retry_after:
            kwargs['retry_after'] = retry_after
        
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class TimeoutError(UnifiedGeneratorError):
    """
    Exception raised when operations exceed their timeout limits.
    
    This includes both connection timeouts and response timeouts.
    """
    
    def __init__(self, message: str = "Operation timed out", 
                 timeout_duration: Optional[float] = None, **kwargs):
        """
        Initialize timeout error.
        
        Args:
            message: Error message
            timeout_duration: The timeout duration that was exceeded
            **kwargs: Additional details
        """
        if timeout_duration:
            kwargs['timeout_duration'] = timeout_duration
        
        super().__init__(message, kwargs)
        self.timeout_duration = timeout_duration


class ValidationError(UnifiedGeneratorError):
    """
    Exception raised for input validation errors.
    
    This includes invalid prompts, malformed parameters, or other
    input validation failures.
    """
    
    def __init__(self, message: str, field: Optional[str] = None,
                 value: Optional[Any] = None, **kwargs):
        """
        Initialize validation error.
        
        Args:
            message: Error message
            field: The field that failed validation
            value: The invalid value
            **kwargs: Additional details
        """
        details = kwargs
        if field:
            details['field'] = field
        if value is not None:
            details['value'] = value
        
        super().__init__(message, details)
        self.field = field
        self.value = value


class RetryExhaustedError(UnifiedGeneratorError):
    """
    Exception raised when all retry attempts have been exhausted.
    
    This exception wraps the original error that caused the retries
    and includes information about the retry attempts.
    """
    
    def __init__(self, message: str, original_error: Exception,
                 retry_count: int, **kwargs):
        """
        Initialize retry exhausted error.
        
        Args:
            message: Error message
            original_error: The original error that caused retries
            retry_count: Number of retry attempts made
            **kwargs: Additional details
        """
        details = kwargs
        details['original_error'] = str(original_error)
        details['original_error_type'] = type(original_error).__name__
        details['retry_count'] = retry_count
        
        super().__init__(message, details)
        self.original_error = original_error
        self.retry_count = retry_count


class ModelNotFoundError(ProviderError):
    """
    Exception raised when a requested model is not available.
    
    This can occur when the model doesn't exist, is not accessible,
    or is temporarily unavailable.
    """
    
    def __init__(self, message: str = "Model not found", **kwargs):
        """
        Initialize model not found error.
        
        Args:
            message: Error message
            **kwargs: Additional details passed to ProviderError
        """
        super().__init__(message, **kwargs)


class ServiceUnavailableError(APIError):
    """
    Exception raised when the API service is unavailable.
    
    This includes server errors, maintenance mode, or other
    temporary service disruptions.
    """
    
    def __init__(self, message: str = "Service unavailable", **kwargs):
        """
        Initialize service unavailable error.
        
        Args:
            message: Error message
            **kwargs: Additional details passed to APIError
        """
        super().__init__(message, **kwargs)


class ContentFilterError(APIError):
    """
    Exception raised when content is filtered by the provider.
    
    This occurs when the input or output content violates the
    provider's content policy.
    """
    
    def __init__(self, message: str = "Content filtered", 
                 filter_reason: Optional[str] = None, **kwargs):
        """
        Initialize content filter error.
        
        Args:
            message: Error message
            filter_reason: Reason for content filtering
            **kwargs: Additional details passed to APIError
        """
        if filter_reason:
            kwargs['filter_reason'] = filter_reason
        
        super().__init__(message, **kwargs)
        self.filter_reason = filter_reason


class HaystackIntegrationError(UnifiedGeneratorError):
    """
    Exception raised for Haystack integration issues.
    
    This includes component initialization errors, pipeline
    connection issues, or serialization problems.
    """
    
    def __init__(self, message: str, component: Optional[str] = None, **kwargs):
        """
        Initialize Haystack integration error.
        
        Args:
            message: Error message
            component: The Haystack component that caused the error
            **kwargs: Additional details
        """
        if component:
            kwargs['component'] = component
        
        super().__init__(message, kwargs)
        self.component = component


# Exception mapping for different error types
ERROR_TYPE_MAPPING = {
    'authentication': AuthenticationError,
    'rate_limit': RateLimitError,
    'timeout': TimeoutError,
    'validation': ValidationError,
    'model_not_found': ModelNotFoundError,
    'service_unavailable': ServiceUnavailableError,
    'content_filter': ContentFilterError,
    'configuration': ConfigurationError,
    'provider': ProviderError,
    'api': APIError,
    'haystack': HaystackIntegrationError,
}


def create_error(error_type: str, message: str, **kwargs) -> UnifiedGeneratorError:
    """
    Factory function to create appropriate error instances.
    
    Args:
        error_type: Type of error to create
        message: Error message
        **kwargs: Additional error details
        
    Returns:
        Appropriate exception instance
        
    Raises:
        ValueError: If error_type is not recognized
    """
    error_class = ERROR_TYPE_MAPPING.get(error_type)
    if not error_class:
        raise ValueError(f"Unknown error type: {error_type}")
    
    return error_class(message, **kwargs)


def is_retryable_error(error: Exception) -> bool:
    """
    Determine if an error is retryable.
    
    Args:
        error: The exception to check
        
    Returns:
        True if the error is retryable, False otherwise
    """
    # Retryable errors
    retryable_types = (
        TimeoutError,
        ServiceUnavailableError,
        RateLimitError,
    )
    
    # Non-retryable errors
    non_retryable_types = (
        AuthenticationError,
        ValidationError,
        ConfigurationError,
        ContentFilterError,
        ModelNotFoundError,
    )
    
    if isinstance(error, non_retryable_types):
        return False
    
    if isinstance(error, retryable_types):
        return True
    
    # For APIError, check status code
    if isinstance(error, APIError) and error.status_code:
        # 5xx errors are generally retryable
        if 500 <= error.status_code < 600:
            return True
        # 429 (rate limit) is retryable
        if error.status_code == 429:
            return True
        # 4xx errors are generally not retryable
        if 400 <= error.status_code < 500:
            return False
    
    # Default to not retryable for unknown errors
    return False