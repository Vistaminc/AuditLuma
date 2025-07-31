"""
Core data models for the unified Haystack generator component.

This module defines the data structures used throughout the unified generator
system, including response models, configuration models, and performance metrics.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class ProviderType(Enum):
    """Supported LLM provider types."""
    OPENAI = "openai"
    OLLAMA = "ollama"
    AUTO = "auto"


class FinishReason(Enum):
    """Possible finish reasons for generation completion."""
    STOP = "stop"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    FUNCTION_CALL = "function_call"
    ERROR = "error"


@dataclass
class GenerationResponse:
    """
    Response data model for LLM generation requests.
    
    This model standardizes the response format across different providers,
    ensuring consistent handling of generation results.
    """
    content: str
    model: str
    provider: str
    usage: Optional[Dict[str, int]] = None
    finish_reason: Optional[str] = None
    response_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate response data after initialization."""
        if not self.content:
            raise ValueError("Generation response content cannot be empty")
        if not self.model:
            raise ValueError("Model name is required")
        if not self.provider:
            raise ValueError("Provider name is required")
        if self.response_time < 0:
            raise ValueError("Response time cannot be negative")


@dataclass
class GeneratorConfig:
    """
    Configuration model for the unified generator.
    
    This model encapsulates all configuration options for the generator,
    including provider-specific settings and general parameters.
    """
    model: str
    provider: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    generation_kwargs: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.model:
            raise ValueError("Model name is required")
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        if self.max_retries < 0:
            raise ValueError("Max retries cannot be negative")
        if self.retry_delay < 0:
            raise ValueError("Retry delay cannot be negative")
    
    def validate(self) -> List[str]:
        """
        Validate configuration and return list of validation errors.
        
        Returns:
            List of validation error messages. Empty list if valid.
        """
        errors = []
        
        # Basic validation
        if not self.model.strip():
            errors.append("Model name cannot be empty")
        
        # Provider-specific validation
        if self.provider:
            if self.provider not in [p.value for p in ProviderType]:
                errors.append(f"Unsupported provider: {self.provider}")
        
        # OpenAI-specific validation
        if self.provider == ProviderType.OPENAI.value:
            if not self.api_key:
                errors.append("API key is required for OpenAI provider")
        
        # Timeout validation
        if self.timeout > 300:  # 5 minutes max
            errors.append("Timeout cannot exceed 300 seconds")
        
        # Retry validation
        if self.max_retries > 10:
            errors.append("Max retries cannot exceed 10")
        
        return errors
    
    def get_provider_type(self) -> ProviderType:
        """
        Determine the provider type from configuration.
        
        Returns:
            ProviderType enum value
        """
        if self.provider:
            try:
                return ProviderType(self.provider)
            except ValueError:
                return ProviderType.AUTO
        
        # Auto-detect from model name
        if "@" in self.model:
            provider_suffix = self.model.split("@")[-1].lower()
            try:
                return ProviderType(provider_suffix)
            except ValueError:
                pass
        
        # Default detection logic
        if self.model.startswith(("gpt-", "text-", "davinci", "curie", "babbage", "ada")):
            return ProviderType.OPENAI
        elif ":" in self.model:  # Ollama format: model:tag
            return ProviderType.OLLAMA
        
        return ProviderType.AUTO


@dataclass
class PerformanceMetrics:
    """
    Performance metrics data model for monitoring provider performance.
    
    This model tracks various performance indicators for each provider
    to enable monitoring and optimization.
    """
    provider: str
    model: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_response_time: float = 0.0
    average_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    last_request_time: Optional[datetime] = None
    error_counts: Dict[str, int] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate metrics after initialization."""
        if not self.provider:
            raise ValueError("Provider name is required")
        if not self.model:
            raise ValueError("Model name is required")
        if self.total_requests < 0:
            raise ValueError("Total requests cannot be negative")
        if self.successful_requests < 0:
            raise ValueError("Successful requests cannot be negative")
        if self.failed_requests < 0:
            raise ValueError("Failed requests cannot be negative")
    
    def record_request(self, response_time: float, success: bool, error_type: Optional[str] = None):
        """
        Record a new request in the metrics.
        
        Args:
            response_time: Time taken for the request in seconds
            success: Whether the request was successful
            error_type: Type of error if request failed
        """
        self.total_requests += 1
        self.total_response_time += response_time
        self.last_request_time = datetime.now()
        
        # Update min/max response times
        if response_time < self.min_response_time:
            self.min_response_time = response_time
        if response_time > self.max_response_time:
            self.max_response_time = response_time
        
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error_type:
                self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Update average response time
        if self.total_requests > 0:
            self.average_response_time = self.total_response_time / self.total_requests
    
    def get_success_rate(self) -> float:
        """
        Calculate the success rate as a percentage.
        
        Returns:
            Success rate between 0.0 and 1.0
        """
        if self.total_requests == 0:
            return 0.0
        return self.successful_requests / self.total_requests
    
    def get_failure_rate(self) -> float:
        """
        Calculate the failure rate as a percentage.
        
        Returns:
            Failure rate between 0.0 and 1.0
        """
        return 1.0 - self.get_success_rate()
    
    def reset(self):
        """Reset all metrics to initial state."""
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_response_time = 0.0
        self.average_response_time = 0.0
        self.min_response_time = float('inf')
        self.max_response_time = 0.0
        self.last_request_time = None
        self.error_counts.clear()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert metrics to dictionary format.
        
        Returns:
            Dictionary representation of metrics
        """
        return {
            'provider': self.provider,
            'model': self.model,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'total_response_time': self.total_response_time,
            'average_response_time': self.average_response_time,
            'min_response_time': self.min_response_time if self.min_response_time != float('inf') else None,
            'max_response_time': self.max_response_time,
            'success_rate': self.get_success_rate(),
            'failure_rate': self.get_failure_rate(),
            'last_request_time': self.last_request_time.isoformat() if self.last_request_time else None,
            'error_counts': self.error_counts.copy()
        }


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior.
    
    This model defines how retries should be handled for failed requests.
    """
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    
    def __post_init__(self):
        """Validate retry configuration."""
        if self.max_retries < 0:
            raise ValueError("Max retries cannot be negative")
        if self.base_delay < 0:
            raise ValueError("Base delay cannot be negative")
        if self.max_delay < self.base_delay:
            raise ValueError("Max delay must be greater than or equal to base delay")
        if self.exponential_base <= 1:
            raise ValueError("Exponential base must be greater than 1")
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for a specific retry attempt.
        
        Args:
            attempt: The retry attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        if attempt < 0:
            return 0.0
        
        delay = self.base_delay * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay)
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random() * 0.5)  # Add 0-50% jitter
        
        return delay


# Type aliases for better code readability
GenerationKwargs = Dict[str, Any]
ProviderConfig = Dict[str, Any]
MetricsDict = Dict[str, Union[int, float, str, datetime]]