"""
Type definitions and enumerations for the unified Haystack generator component.

This module provides type hints, constants, and utility types used throughout
the unified generator system.
"""

from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Union
from abc import ABC, abstractmethod


# Basic type aliases
GenerationKwargs = Dict[str, Any]
ProviderConfig = Dict[str, Any]
MetricsDict = Dict[str, Union[int, float, str]]
Headers = Dict[str, str]
QueryParams = Dict[str, Union[str, int, float, bool]]


class LogLevel(Enum):
    """Logging levels for the unified generator."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RequestMethod(Enum):
    """HTTP request methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class ContentType(Enum):
    """Common content types for API requests."""
    JSON = "application/json"
    FORM_URLENCODED = "application/x-www-form-urlencoded"
    TEXT_PLAIN = "text/plain"
    MULTIPART_FORM = "multipart/form-data"


class ModelCapability(Enum):
    """Capabilities that models may support."""
    TEXT_GENERATION = "text_generation"
    CHAT_COMPLETION = "chat_completion"
    FUNCTION_CALLING = "function_calling"
    STREAMING = "streaming"
    EMBEDDINGS = "embeddings"
    IMAGE_UNDERSTANDING = "image_understanding"
    CODE_GENERATION = "code_generation"


class ProviderStatus(Enum):
    """Status of a provider connection."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


# Protocol definitions for type checking
class Serializable(Protocol):
    """Protocol for objects that can be serialized."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert object to dictionary representation."""
        ...
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Serializable':
        """Create object from dictionary representation."""
        ...


class Configurable(Protocol):
    """Protocol for configurable objects."""
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure the object with provided settings."""
        ...
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        ...


class Monitorable(Protocol):
    """Protocol for objects that can be monitored."""
    
    def get_health_status(self) -> ProviderStatus:
        """Get current health status."""
        ...
    
    def get_metrics(self) -> MetricsDict:
        """Get current metrics."""
        ...


class AsyncCallable(Protocol):
    """Protocol for async callable objects."""
    
    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Async call method."""
        ...


# Callback type definitions
ErrorCallback = Callable[[Exception], None]
SuccessCallback = Callable[[Any], None]
ProgressCallback = Callable[[float], None]
LogCallback = Callable[[LogLevel, str], None]


# Configuration constants
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0
DEFAULT_MAX_DELAY = 60.0
DEFAULT_EXPONENTIAL_BASE = 2.0

# OpenAI specific constants
OPENAI_DEFAULT_BASE_URL = "https://api.openai.com/v1"
OPENAI_DEFAULT_MODEL = "gpt-3.5-turbo"
OPENAI_MAX_TOKENS_LIMIT = 4096
OPENAI_TEMPERATURE_RANGE = (0.0, 2.0)
OPENAI_TOP_P_RANGE = (0.0, 1.0)

# Ollama specific constants
OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434"
OLLAMA_DEFAULT_TIMEOUT = 60.0
OLLAMA_API_VERSION = "v1"

# Model name patterns
OPENAI_MODEL_PATTERNS = [
    r"^gpt-\d+(\.\d+)?(-turbo)?(-\d+k)?$",
    r"^text-(davinci|curie|babbage|ada)-\d+$",
    r"^(davinci|curie|babbage|ada)$",
]

OLLAMA_MODEL_PATTERNS = [
    r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+$",  # model:tag format
    r"^[a-zA-Z0-9_-]+$",  # simple model name
]

# Error codes
class ErrorCode(Enum):
    """Standard error codes for the unified generator."""
    
    # Configuration errors (1000-1099)
    INVALID_CONFIG = 1000
    MISSING_CONFIG = 1001
    CONFIG_VALIDATION_FAILED = 1002
    
    # Provider errors (1100-1199)
    PROVIDER_NOT_FOUND = 1100
    PROVIDER_INITIALIZATION_FAILED = 1101
    PROVIDER_NOT_SUPPORTED = 1102
    
    # Authentication errors (1200-1299)
    INVALID_API_KEY = 1200
    AUTHENTICATION_FAILED = 1201
    INSUFFICIENT_PERMISSIONS = 1202
    
    # API errors (1300-1399)
    API_REQUEST_FAILED = 1300
    INVALID_RESPONSE = 1301
    RATE_LIMIT_EXCEEDED = 1302
    SERVICE_UNAVAILABLE = 1303
    
    # Model errors (1400-1499)
    MODEL_NOT_FOUND = 1400
    MODEL_NOT_SUPPORTED = 1401
    MODEL_OVERLOADED = 1402
    
    # Validation errors (1500-1599)
    INVALID_INPUT = 1500
    PROMPT_TOO_LONG = 1501
    INVALID_PARAMETERS = 1502
    
    # Timeout errors (1600-1699)
    CONNECTION_TIMEOUT = 1600
    REQUEST_TIMEOUT = 1601
    RESPONSE_TIMEOUT = 1602
    
    # Content errors (1700-1799)
    CONTENT_FILTERED = 1700
    CONTENT_TOO_LONG = 1701
    INVALID_CONTENT_TYPE = 1702
    
    # System errors (1800-1899)
    INTERNAL_ERROR = 1800
    RESOURCE_EXHAUSTED = 1801
    DEPENDENCY_FAILED = 1802


# HTTP status code mappings
HTTP_STATUS_TO_ERROR_CODE = {
    400: ErrorCode.INVALID_INPUT,
    401: ErrorCode.AUTHENTICATION_FAILED,
    403: ErrorCode.INSUFFICIENT_PERMISSIONS,
    404: ErrorCode.MODEL_NOT_FOUND,
    408: ErrorCode.REQUEST_TIMEOUT,
    429: ErrorCode.RATE_LIMIT_EXCEEDED,
    500: ErrorCode.INTERNAL_ERROR,
    502: ErrorCode.SERVICE_UNAVAILABLE,
    503: ErrorCode.SERVICE_UNAVAILABLE,
    504: ErrorCode.RESPONSE_TIMEOUT,
}


# Utility type guards
def is_openai_model(model_name: str) -> bool:
    """
    Check if a model name matches OpenAI patterns.
    
    Args:
        model_name: The model name to check
        
    Returns:
        True if the model appears to be an OpenAI model
    """
    import re
    
    for pattern in OPENAI_MODEL_PATTERNS:
        if re.match(pattern, model_name, re.IGNORECASE):
            return True
    
    return False


def is_ollama_model(model_name: str) -> bool:
    """
    Check if a model name matches Ollama patterns.
    
    Args:
        model_name: The model name to check
        
    Returns:
        True if the model appears to be an Ollama model
    """
    import re
    
    for pattern in OLLAMA_MODEL_PATTERNS:
        if re.match(pattern, model_name):
            return True
    
    return False


def extract_provider_from_model(model_name: str) -> Optional[str]:
    """
    Extract provider name from model specification.
    
    Args:
        model_name: Model name potentially with @provider suffix
        
    Returns:
        Provider name if found, None otherwise
    """
    if "@" in model_name:
        return model_name.split("@")[-1].lower()
    return None


def clean_model_name(model_name: str) -> str:
    """
    Clean model name by removing provider suffix.
    
    Args:
        model_name: Model name potentially with @provider suffix
        
    Returns:
        Clean model name without provider suffix
    """
    if "@" in model_name:
        return model_name.split("@")[0]
    return model_name


# Validation utilities
def validate_timeout(timeout: float) -> bool:
    """Validate timeout value."""
    return 0 < timeout <= 300  # Max 5 minutes


def validate_retry_count(retries: int) -> bool:
    """Validate retry count."""
    return 0 <= retries <= 10


def validate_temperature(temperature: float) -> bool:
    """Validate temperature parameter."""
    return OPENAI_TEMPERATURE_RANGE[0] <= temperature <= OPENAI_TEMPERATURE_RANGE[1]


def validate_top_p(top_p: float) -> bool:
    """Validate top_p parameter."""
    return OPENAI_TOP_P_RANGE[0] <= top_p <= OPENAI_TOP_P_RANGE[1]


def validate_max_tokens(max_tokens: int) -> bool:
    """Validate max_tokens parameter."""
    return 1 <= max_tokens <= OPENAI_MAX_TOKENS_LIMIT


# Type conversion utilities
def safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert value to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes', 'on')
    if isinstance(value, (int, float)):
        return bool(value)
    return default