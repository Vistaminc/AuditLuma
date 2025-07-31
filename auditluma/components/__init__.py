"""
AuditLuma Components Package

This package contains reusable components for the AuditLuma system,
including the unified Haystack generator component.
"""

# Import core models and types
from .models import (
    GenerationResponse,
    GeneratorConfig,
    PerformanceMetrics,
    RetryConfig,
    ProviderType,
    FinishReason,
)

from .exceptions import (
    UnifiedGeneratorError,
    ConfigurationError,
    ProviderError,
    APIError,
    AuthenticationError,
    RateLimitError,
    TimeoutError,
    ValidationError,
    RetryExhaustedError,
    ModelNotFoundError,
    ServiceUnavailableError,
    ContentFilterError,
    HaystackIntegrationError,
    create_error,
    is_retryable_error,
)

from .types import (
    LogLevel,
    RequestMethod,
    ContentType,
    ModelCapability,
    ProviderStatus,
    ErrorCode,
    GenerationKwargs,
    ProviderConfig,
    MetricsDict,
    is_openai_model,
    is_ollama_model,
    extract_provider_from_model,
    clean_model_name,
)

# Import base classes and interfaces
from .base import (
    LLMClient,
    ConfigurableClient,
    StreamingClient,
    BatchClient,
    ProviderDetector,
    ClientFactory,
    supports_streaming,
    supports_batch_processing,
    supports_dynamic_config,
    get_client_capabilities,
)

# Import detection and validation utilities
from .detection import (
    DefaultProviderDetector,
    ConfigBasedDetector,
    CompositeDetector,
    detect_provider,
    get_provider_confidence,
    get_supported_providers,
    validate_model_provider_pair,
)

from .validation import (
    ConfigValidator,
    validate_config,
    validate_model_name,
    validate_generation_parameters,
    is_valid_config,
    raise_for_invalid_config,
)

# Import client implementations
from .openai_client import OpenAIClient
from .ollama_client import OllamaClient

# Import factory and registry
from .factory import (
    UnifiedClientFactory, ProviderRegistry, create_client,
    get_supported_providers, register_custom_client
)

# Import configuration management
from .config_manager import (
    ConfigurationManager, get_config_manager, create_config_from_manager,
    validate_managed_config
)

# Import retry management
from .retry_manager import (
    RetryManager, RetryConfig, RetryStrategy, CircuitBreakerConfig,
    CircuitBreaker, RetryAttempt, ErrorClassifier,
    DEFAULT_RETRY_CONFIG, AGGRESSIVE_RETRY_CONFIG, CONSERVATIVE_RETRY_CONFIG,
    DEFAULT_CIRCUIT_BREAKER_CONFIG, SENSITIVE_CIRCUIT_BREAKER_CONFIG,
    create_retry_manager, with_retry
)

# Import main component
from .unified_generator import (
    UnifiedGenerator, create_unified_generator, create_openai_generator,
    create_ollama_generator
)

__all__ = [
    # Models
    "GenerationResponse",
    "GeneratorConfig", 
    "PerformanceMetrics",
    "RetryConfig",
    "ProviderType",
    "FinishReason",
    
    # Exceptions
    "UnifiedGeneratorError",
    "ConfigurationError",
    "ProviderError",
    "APIError",
    "AuthenticationError",
    "RateLimitError",
    "TimeoutError",
    "ValidationError",
    "RetryExhaustedError",
    "ModelNotFoundError",
    "ServiceUnavailableError",
    "ContentFilterError",
    "HaystackIntegrationError",
    "create_error",
    "is_retryable_error",
    
    # Types and utilities
    "LogLevel",
    "RequestMethod",
    "ContentType",
    "ModelCapability",
    "ProviderStatus",
    "ErrorCode",
    "GenerationKwargs",
    "ProviderConfig",
    "MetricsDict",
    "is_openai_model",
    "is_ollama_model",
    "extract_provider_from_model",
    "clean_model_name",
    
    # Base classes and interfaces
    "LLMClient",
    "ConfigurableClient",
    "StreamingClient",
    "BatchClient",
    "ProviderDetector",
    "ClientFactory",
    "supports_streaming",
    "supports_batch_processing",
    "supports_dynamic_config",
    "get_client_capabilities",
    
    # Detection and validation
    "DefaultProviderDetector",
    "ConfigBasedDetector",
    "CompositeDetector",
    "detect_provider",
    "get_provider_confidence",
    "get_supported_providers",
    "validate_model_provider_pair",
    "ConfigValidator",
    "validate_config",
    "validate_model_name",
    "validate_generation_parameters",
    "is_valid_config",
    "raise_for_invalid_config",
    
    # Client implementations
    "OpenAIClient",
    "OllamaClient",
    
    # Factory and registry
    "UnifiedClientFactory",
    "ProviderRegistry",
    "create_client",
    "get_supported_providers",
    "register_custom_client",
    
    # Configuration management
    "ConfigurationManager",
    "get_config_manager",
    "create_config_from_manager",
    "validate_managed_config",
    
    # Retry management
    "RetryManager",
    "RetryConfig", 
    "RetryStrategy",
    "CircuitBreakerConfig",
    "CircuitBreaker",
    "RetryAttempt",
    "ErrorClassifier",
    "DEFAULT_RETRY_CONFIG",
    "AGGRESSIVE_RETRY_CONFIG",
    "CONSERVATIVE_RETRY_CONFIG",
    "DEFAULT_CIRCUIT_BREAKER_CONFIG",
    "SENSITIVE_CIRCUIT_BREAKER_CONFIG",
    "create_retry_manager",
    "with_retry",
    
    # Main component
    "UnifiedGenerator",
    "create_unified_generator",
    "create_openai_generator", 
    "create_ollama_generator",
]