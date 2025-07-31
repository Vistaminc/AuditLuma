"""
Unified Haystack Generator Component

This module provides a unified generator component that supports both OpenAI and Ollama APIs,
integrating seamlessly with Haystack pipelines while providing comprehensive error handling,
retry mechanisms, and performance monitoring.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Union, Type
from datetime import datetime

try:
    from haystack import component, default_from_dict, default_to_dict
    from haystack.core.component import ComponentConfig
    from haystack.core.serialization import DeserializationCallbacks
    HAYSTACK_AVAILABLE = True
except ImportError:
    # Fallback for when Haystack is not available
    HAYSTACK_AVAILABLE = False
    
    def component(cls):
        return cls
    
    def default_from_dict(data):
        return data
    
    def default_to_dict(obj):
        return obj.__dict__

from .models import GeneratorConfig, GenerationResponse, PerformanceMetrics
from .exceptions import (
    UnifiedGeneratorError, ConfigurationError, ProviderError,
    RetryExhaustedError, HaystackIntegrationError
)
from .factory import UnifiedClientFactory
from .config_manager import ConfigurationManager, get_config_manager
from .retry_manager import RetryManager, RetryConfig, DEFAULT_RETRY_CONFIG
from .base import LLMClient

logger = logging.getLogger(__name__)


@component
class UnifiedGenerator:
    """
    Unified generator component for Haystack pipelines.
    
    This component provides a unified interface to multiple LLM providers
    (OpenAI, Ollama, etc.) with comprehensive error handling, retry mechanisms,
    and performance monitoring.
    """
    
    def __init__(
        self,
        model: str,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        provider: Optional[str] = None,
        generation_kwargs: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        config_manager: Optional[ConfigurationManager] = None,
        retry_config: Optional[RetryConfig] = None,
        enable_monitoring: bool = True,
        **kwargs
    ):
        """
        Initialize the UnifiedGenerator component.
        
        Args:
            model: Model name (e.g., "gpt-4", "qwen3:32b", "gpt-4@openai")
            api_key: API key for the provider (if required)
            base_url: Base URL for the API endpoint
            provider: Provider name (auto-detected if not specified)
            generation_kwargs: Additional parameters for generation
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Base delay between retries in seconds
            config_manager: Configuration manager instance
            retry_config: Retry configuration
            enable_monitoring: Whether to enable performance monitoring
            **kwargs: Additional configuration parameters
        """
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.provider = provider
        self.generation_kwargs = generation_kwargs or {}
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enable_monitoring = enable_monitoring
        
        # Initialize configuration manager
        self.config_manager = config_manager or get_config_manager()
        
        # Initialize retry manager
        if retry_config is None:
            retry_config = RetryConfig(
                max_attempts=max_retries,
                base_delay=retry_delay,
                timeout=timeout
            )
        self.retry_manager = RetryManager(retry_config)
        
        # Initialize client factory
        self.client_factory = UnifiedClientFactory()
        
        # Initialize performance metrics
        self.performance_metrics = PerformanceMetrics(
            provider=provider or "unknown",
            model=model
        )
        
        # Initialize client (lazy loading)
        self._client: Optional[LLMClient] = None
        self._client_config: Optional[GeneratorConfig] = None
        
        # Component metadata
        self._component_config = {
            'model': model,
            'provider': provider,
            'timeout': timeout,
            'max_retries': max_retries,
            'enable_monitoring': enable_monitoring
        }
        
        logger.info(f"Initialized UnifiedGenerator with model: {model}")
    
    def _get_client(self) -> LLMClient:
        """
        Get or create the LLM client instance.
        
        Returns:
            LLM client instance
            
        Raises:
            ConfigurationError: If client configuration is invalid
            ProviderError: If provider detection fails
        """
        if self._client is None:
            try:
                # Create generator config
                self._client_config = self.config_manager.create_generator_config(
                    model=self.model,
                    provider=self.provider,
                    api_key=self.api_key,
                    base_url=self.base_url,
                    timeout=self.timeout,
                    max_retries=self.max_retries,
                    retry_delay=self.retry_delay,
                    generation_kwargs=self.generation_kwargs
                )
                
                # Create client using factory
                self._client = self.client_factory.create_client(self._client_config)
                
                logger.info(f"Created client for provider: {self._client_config.provider}")
                
            except Exception as e:
                error_msg = f"Failed to create client for model {self.model}: {e}"
                logger.error(error_msg)
                raise ConfigurationError(error_msg) from e
        
        return self._client
    
    def _record_metrics(self, start_time: float, success: bool, error: Optional[Exception] = None):
        """
        Record performance metrics.
        
        Args:
            start_time: Request start time
            success: Whether the request was successful
            error: Error that occurred (if any)
        """
        if not self.enable_monitoring:
            return
        
        response_time = time.time() - start_time
        
        self.performance_metrics.total_requests += 1
        self.performance_metrics.total_response_time += response_time
        
        if success:
            self.performance_metrics.successful_requests += 1
        else:
            self.performance_metrics.failed_requests += 1
            if error:
                error_type = type(error).__name__
                self.performance_metrics.error_counts[error_type] = (
                    self.performance_metrics.error_counts.get(error_type, 0) + 1
                )
        
        # Update min/max response times
        if (self.performance_metrics.min_response_time is None or 
            response_time < self.performance_metrics.min_response_time):
            self.performance_metrics.min_response_time = response_time
        
        if (self.performance_metrics.max_response_time is None or 
            response_time > self.performance_metrics.max_response_time):
            self.performance_metrics.max_response_time = response_time
    
    @component.output_types(replies=List[str], meta=List[Dict[str, Any]])
    def run(
        self,
        prompt: str,
        generation_kwargs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate text using the configured LLM provider.
        
        Args:
            prompt: Input prompt for text generation
            generation_kwargs: Additional generation parameters
            
        Returns:
            Dictionary containing generated replies and metadata
            
        Raises:
            UnifiedGeneratorError: If generation fails
        """
        if not prompt:
            raise ValueError("Prompt cannot be empty")
        
        start_time = time.time()
        error = None
        
        try:
            # Merge generation kwargs
            merged_kwargs = self.generation_kwargs.copy()
            if generation_kwargs:
                merged_kwargs.update(generation_kwargs)
            
            # Get client
            client = self._get_client()
            
            # Execute generation with retry
            async def _generate():
                return await client.generate(prompt, **merged_kwargs)
            
            # Use retry manager for execution
            import asyncio
            if asyncio.iscoroutinefunction(client.generate):
                response = asyncio.run(
                    self.retry_manager.execute_with_retry(_generate)
                )
            else:
                # Synchronous client
                def _sync_generate():
                    return client.generate(prompt, **merged_kwargs)
                
                response = asyncio.run(
                    self.retry_manager.execute_with_retry(_sync_generate)
                )
            
            # Record successful metrics
            self._record_metrics(start_time, success=True)
            
            # Prepare output in Haystack format
            replies = [response.content] if response.content else []
            meta = [{
                'model': self.model,
                'provider': self._client_config.provider if self._client_config else 'unknown',
                'finish_reason': response.finish_reason.value if response.finish_reason else 'unknown',
                'usage': response.usage,
                'response_time': time.time() - start_time,
                'timestamp': datetime.now().isoformat()
            }]
            
            logger.debug(f"Generated {len(replies)} replies for model {self.model}")
            
            return {
                'replies': replies,
                'meta': meta
            }
            
        except Exception as e:
            error = e
            self._record_metrics(start_time, success=False, error=error)
            
            # Wrap in appropriate exception type
            if isinstance(e, UnifiedGeneratorError):
                raise
            elif isinstance(e, RetryExhaustedError):
                raise UnifiedGeneratorError(
                    f"Generation failed after {e.retry_count} retries: {e.original_error}"
                ) from e
            else:
                raise UnifiedGeneratorError(f"Generation failed: {e}") from e
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get performance metrics for this generator instance.
        
        Returns:
            Dictionary containing performance metrics
        """
        if not self.enable_monitoring:
            return {'monitoring_disabled': True}
        
        metrics = self.performance_metrics.to_dict()
        
        # Add retry manager statistics
        retry_stats = self.retry_manager.get_retry_statistics()
        metrics['retry_statistics'] = retry_stats
        
        return metrics
    
    def reset_metrics(self):
        """Reset performance metrics."""
        if self.enable_monitoring:
            self.performance_metrics = PerformanceMetrics(
                provider=self.provider or "unknown",
                model=self.model
            )
            self.retry_manager.reset_statistics()
    
    def validate_config(self) -> List[str]:
        """
        Validate the current configuration.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        try:
            # Validate basic parameters
            if not self.model:
                errors.append("Model name is required")
            
            if self.timeout <= 0:
                errors.append("Timeout must be positive")
            
            if self.max_retries < 0:
                errors.append("Max retries must be non-negative")
            
            # Try to create client config to validate
            try:
                config = self.config_manager.create_generator_config(
                    model=self.model,
                    provider=self.provider,
                    api_key=self.api_key,
                    base_url=self.base_url
                )
                
                # Validate client creation
                self.client_factory.create_client(config)
                
            except Exception as e:
                errors.append(f"Client configuration error: {e}")
        
        except Exception as e:
            errors.append(f"Configuration validation error: {e}")
        
        return errors
    
    def get_component_info(self) -> Dict[str, Any]:
        """
        Get component information for debugging and monitoring.
        
        Returns:
            Dictionary containing component information
        """
        info = {
            'component_type': 'UnifiedGenerator',
            'model': self.model,
            'provider': self.provider,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'enable_monitoring': self.enable_monitoring,
            'client_initialized': self._client is not None,
            'haystack_available': HAYSTACK_AVAILABLE
        }
        
        if self._client_config:
            info['effective_provider'] = self._client_config.provider
            info['effective_model'] = self._client_config.model
        
        return info
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize component to dictionary for Haystack serialization.
        
        Returns:
            Dictionary representation of the component
        """
        if HAYSTACK_AVAILABLE:
            return default_to_dict(
                self,
                model=self.model,
                api_key=self.api_key,
                base_url=self.base_url,
                provider=self.provider,
                generation_kwargs=self.generation_kwargs,
                timeout=self.timeout,
                max_retries=self.max_retries,
                retry_delay=self.retry_delay,
                enable_monitoring=self.enable_monitoring
            )
        else:
            return {
                'init_parameters': {
                    'model': self.model,
                    'api_key': self.api_key,
                    'base_url': self.base_url,
                    'provider': self.provider,
                    'generation_kwargs': self.generation_kwargs,
                    'timeout': self.timeout,
                    'max_retries': self.max_retries,
                    'retry_delay': self.retry_delay,
                    'enable_monitoring': self.enable_monitoring
                }
            }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnifiedGenerator":
        """
        Deserialize component from dictionary for Haystack serialization.
        
        Args:
            data: Dictionary representation of the component
            
        Returns:
            UnifiedGenerator instance
        """
        init_params = data.get("init_parameters", {})
        if "model" not in init_params:
            raise ValueError("Model parameter is required for deserialization")
        
        if HAYSTACK_AVAILABLE:
            return default_from_dict(cls, data)
        else:
            return cls(**init_params)
    
    def __repr__(self) -> str:
        """String representation of the component."""
        return (
            f"UnifiedGenerator(model='{self.model}', "
            f"provider='{self.provider}', "
            f"timeout={self.timeout})"
        )


# Remove the decorator application since it's now applied directly to the class


# Convenience functions for creating UnifiedGenerator instances

def create_unified_generator(
    model: str,
    provider: Optional[str] = None,
    **kwargs
) -> UnifiedGenerator:
    """
    Create a UnifiedGenerator instance with sensible defaults.
    
    Args:
        model: Model name
        provider: Provider name (auto-detected if not specified)
        **kwargs: Additional configuration parameters
        
    Returns:
        UnifiedGenerator instance
    """
    return UnifiedGenerator(model=model, provider=provider, **kwargs)


def create_openai_generator(
    model: str = "gpt-3.5-turbo",
    api_key: Optional[str] = None,
    **kwargs
) -> UnifiedGenerator:
    """
    Create a UnifiedGenerator configured for OpenAI.
    
    Args:
        model: OpenAI model name
        api_key: OpenAI API key
        **kwargs: Additional configuration parameters
        
    Returns:
        UnifiedGenerator instance configured for OpenAI
    """
    return UnifiedGenerator(
        model=model,
        provider="openai",
        api_key=api_key,
        **kwargs
    )


def create_ollama_generator(
    model: str = "qwen3:32b",
    base_url: Optional[str] = None,
    **kwargs
) -> UnifiedGenerator:
    """
    Create a UnifiedGenerator configured for Ollama.
    
    Args:
        model: Ollama model name
        base_url: Ollama service URL
        **kwargs: Additional configuration parameters
        
    Returns:
        UnifiedGenerator instance configured for Ollama
    """
    return UnifiedGenerator(
        model=model,
        provider="ollama",
        base_url=base_url,
        **kwargs
    )