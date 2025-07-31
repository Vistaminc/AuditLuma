"""
Abstract base classes and interfaces for the unified Haystack generator component.

This module defines the core interfaces that all LLM clients must implement,
providing a consistent API across different providers.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, AsyncIterator
from datetime import datetime

from .models import GenerationResponse, GeneratorConfig, PerformanceMetrics
from .exceptions import UnifiedGeneratorError, ValidationError, ConfigurationError
from .types import ProviderStatus, ModelCapability


class LLMClient(ABC):
    """
    Abstract base class for all LLM clients.
    
    This class defines the interface that all provider-specific clients
    must implement to ensure consistent behavior across different LLM providers.
    """
    
    def __init__(self, config: GeneratorConfig):
        """
        Initialize the LLM client with configuration.
        
        Args:
            config: Generator configuration containing provider-specific settings
        """
        self.config = config
        self._metrics = PerformanceMetrics(
            provider=self.get_provider_name(),
            model=config.model
        )
        self._initialized = False
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        generation_kwargs: Optional[Dict[str, Any]] = None
    ) -> GenerationResponse:
        """
        Generate text using the LLM.
        
        Args:
            prompt: Input prompt for generation
            generation_kwargs: Additional generation parameters
            
        Returns:
            GenerationResponse containing the generated text and metadata
            
        Raises:
            UnifiedGeneratorError: If generation fails
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> List[str]:
        """
        Validate the client configuration.
        
        Returns:
            List of validation error messages. Empty list if valid.
        """
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """
        Get the name of the provider.
        
        Returns:
            Provider name (e.g., "openai", "ollama")
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> ProviderStatus:
        """
        Check the health status of the provider.
        
        Returns:
            Current health status of the provider
        """
        pass
    
    @abstractmethod
    def get_supported_capabilities(self) -> List[ModelCapability]:
        """
        Get the capabilities supported by this client.
        
        Returns:
            List of supported model capabilities
        """
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the client and establish connections.
        
        This method should be called before using the client for generation.
        
        Raises:
            ConfigurationError: If initialization fails due to configuration issues
            UnifiedGeneratorError: If initialization fails for other reasons
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """
        Clean up resources and close connections.
        
        This method should be called when the client is no longer needed.
        """
        pass
    
    # Common methods with default implementations
    
    def get_metrics(self) -> PerformanceMetrics:
        """
        Get performance metrics for this client.
        
        Returns:
            Current performance metrics
        """
        return self._metrics
    
    def reset_metrics(self) -> None:
        """Reset performance metrics to initial state."""
        self._metrics.reset()
    
    def is_initialized(self) -> bool:
        """
        Check if the client has been initialized.
        
        Returns:
            True if the client is initialized and ready to use
        """
        return self._initialized
    
    def validate_prompt(self, prompt: str) -> None:
        """
        Validate the input prompt.
        
        Args:
            prompt: The prompt to validate
            
        Raises:
            ValidationError: If the prompt is invalid
        """
        if not prompt or not prompt.strip():
            raise ValidationError("Prompt cannot be empty", field="prompt", value=prompt)
        
        # Check prompt length (provider-specific limits should be implemented in subclasses)
        if len(prompt) > 100000:  # General sanity check
            raise ValidationError(
                "Prompt is too long",
                field="prompt",
                value=f"Length: {len(prompt)}"
            )
    
    def validate_generation_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and normalize generation parameters.
        
        Args:
            kwargs: Generation parameters to validate
            
        Returns:
            Validated and normalized parameters
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not kwargs:
            return {}
        
        validated = {}
        
        # Common parameter validation
        if "temperature" in kwargs:
            temp = kwargs["temperature"]
            if not isinstance(temp, (int, float)) or temp < 0 or temp > 2:
                raise ValidationError(
                    "Temperature must be between 0 and 2",
                    field="temperature",
                    value=temp
                )
            validated["temperature"] = float(temp)
        
        if "max_tokens" in kwargs:
            max_tokens = kwargs["max_tokens"]
            if not isinstance(max_tokens, int) or max_tokens < 1:
                raise ValidationError(
                    "max_tokens must be a positive integer",
                    field="max_tokens",
                    value=max_tokens
                )
            validated["max_tokens"] = max_tokens
        
        if "top_p" in kwargs:
            top_p = kwargs["top_p"]
            if not isinstance(top_p, (int, float)) or top_p < 0 or top_p > 1:
                raise ValidationError(
                    "top_p must be between 0 and 1",
                    field="top_p",
                    value=top_p
                )
            validated["top_p"] = float(top_p)
        
        # Copy other parameters (provider-specific validation in subclasses)
        for key, value in kwargs.items():
            if key not in validated:
                validated[key] = value
        
        return validated
    
    async def _record_request(
        self,
        start_time: datetime,
        success: bool,
        error_type: Optional[str] = None
    ) -> None:
        """
        Record request metrics.
        
        Args:
            start_time: When the request started
            success: Whether the request was successful
            error_type: Type of error if request failed
        """
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        
        self._metrics.record_request(
            response_time=response_time,
            success=success,
            error_type=error_type
        )


class ConfigurableClient(ABC):
    """
    Abstract base class for clients that support dynamic configuration.
    
    This interface allows clients to be reconfigured at runtime without
    requiring a complete restart.
    """
    
    @abstractmethod
    async def update_config(self, new_config: GeneratorConfig) -> None:
        """
        Update the client configuration.
        
        Args:
            new_config: New configuration to apply
            
        Raises:
            ConfigurationError: If the new configuration is invalid
            UnifiedGeneratorError: If configuration update fails
        """
        pass
    
    @abstractmethod
    def get_current_config(self) -> GeneratorConfig:
        """
        Get the current configuration.
        
        Returns:
            Current generator configuration
        """
        pass


class StreamingClient(ABC):
    """
    Abstract base class for clients that support streaming responses.
    
    This interface allows clients to provide streaming text generation
    for real-time applications.
    """
    
    @abstractmethod
    async def generate_stream(
        self,
        prompt: str,
        generation_kwargs: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[str]:
        """
        Generate text with streaming response.
        
        Args:
            prompt: Input prompt for generation
            generation_kwargs: Additional generation parameters
            
        Yields:
            Chunks of generated text as they become available
            
        Raises:
            UnifiedGeneratorError: If streaming generation fails
        """
        pass
    
    @abstractmethod
    def supports_streaming(self) -> bool:
        """
        Check if the client supports streaming.
        
        Returns:
            True if streaming is supported
        """
        pass


class BatchClient(ABC):
    """
    Abstract base class for clients that support batch processing.
    
    This interface allows clients to process multiple prompts efficiently
    in a single batch request.
    """
    
    @abstractmethod
    async def generate_batch(
        self,
        prompts: List[str],
        generation_kwargs: Optional[Dict[str, Any]] = None
    ) -> List[GenerationResponse]:
        """
        Generate text for multiple prompts in a batch.
        
        Args:
            prompts: List of input prompts
            generation_kwargs: Additional generation parameters
            
        Returns:
            List of generation responses, one for each prompt
            
        Raises:
            UnifiedGeneratorError: If batch generation fails
        """
        pass
    
    @abstractmethod
    def get_max_batch_size(self) -> int:
        """
        Get the maximum supported batch size.
        
        Returns:
            Maximum number of prompts that can be processed in a single batch
        """
        pass


class ProviderDetector(ABC):
    """
    Abstract base class for provider detection logic.
    
    This interface allows for pluggable provider detection strategies
    based on model names, configurations, or other criteria.
    """
    
    @abstractmethod
    def detect_provider(self, model: str, config: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Detect the provider for a given model.
        
        Args:
            model: Model name to analyze
            config: Optional configuration context
            
        Returns:
            Provider name if detected, None if unable to determine
        """
        pass
    
    @abstractmethod
    def get_supported_providers(self) -> List[str]:
        """
        Get list of providers this detector can identify.
        
        Returns:
            List of supported provider names
        """
        pass
    
    @abstractmethod
    def get_confidence_score(self, model: str, provider: str) -> float:
        """
        Get confidence score for a model-provider pairing.
        
        Args:
            model: Model name
            provider: Provider name
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        pass


class ClientFactory(ABC):
    """
    Abstract base class for client factories.
    
    This interface allows for pluggable client creation strategies
    and supports different provider implementations.
    """
    
    @abstractmethod
    def create_client(self, config: GeneratorConfig) -> LLMClient:
        """
        Create an LLM client based on configuration.
        
        Args:
            config: Generator configuration
            
        Returns:
            Configured LLM client instance
            
        Raises:
            ConfigurationError: If configuration is invalid
            UnifiedGeneratorError: If client creation fails
        """
        pass
    
    @abstractmethod
    def get_supported_providers(self) -> List[str]:
        """
        Get list of providers this factory can create clients for.
        
        Returns:
            List of supported provider names
        """
        pass
    
    @abstractmethod
    def validate_provider_config(self, provider: str, config: Dict[str, Any]) -> List[str]:
        """
        Validate provider-specific configuration.
        
        Args:
            provider: Provider name
            config: Configuration to validate
            
        Returns:
            List of validation error messages
        """
        pass


# Type aliases for better code readability
ClientType = Union[LLMClient, ConfigurableClient, StreamingClient, BatchClient]
FactoryType = Union[ClientFactory]
DetectorType = Union[ProviderDetector]


# Utility functions for interface checking
def supports_streaming(client: LLMClient) -> bool:
    """
    Check if a client supports streaming.
    
    Args:
        client: LLM client to check
        
    Returns:
        True if the client supports streaming
    """
    return isinstance(client, StreamingClient) and client.supports_streaming()


def supports_batch_processing(client: LLMClient) -> bool:
    """
    Check if a client supports batch processing.
    
    Args:
        client: LLM client to check
        
    Returns:
        True if the client supports batch processing
    """
    return isinstance(client, BatchClient)


def supports_dynamic_config(client: LLMClient) -> bool:
    """
    Check if a client supports dynamic configuration updates.
    
    Args:
        client: LLM client to check
        
    Returns:
        True if the client supports configuration updates
    """
    return isinstance(client, ConfigurableClient)


def get_client_capabilities(client: LLMClient) -> Dict[str, bool]:
    """
    Get a summary of client capabilities.
    
    Args:
        client: LLM client to analyze
        
    Returns:
        Dictionary mapping capability names to availability
    """
    return {
        "streaming": supports_streaming(client),
        "batch_processing": supports_batch_processing(client),
        "dynamic_config": supports_dynamic_config(client),
        "health_check": hasattr(client, "health_check"),
        "metrics": hasattr(client, "get_metrics"),
    }