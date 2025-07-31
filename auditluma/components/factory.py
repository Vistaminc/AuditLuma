"""
Provider factory and client creation logic for the unified Haystack generator.

This module provides concrete implementations of the ClientFactory interface
and integrates provider detection with client instantiation.
"""

from typing import Any, Dict, List, Optional, Type
import logging

from .base import LLMClient, ClientFactory
from .models import GeneratorConfig, ProviderType
from .exceptions import ConfigurationError, ProviderError
from .detection import detect_provider, get_provider_confidence, CompositeDetector
from .validation import validate_config
from .openai_client import OpenAIClient
from .ollama_client import OllamaClient

logger = logging.getLogger(__name__)


class UnifiedClientFactory(ClientFactory):
    """
    Unified client factory that creates appropriate LLM clients based on configuration.
    
    This factory uses provider detection logic to automatically determine the
    appropriate client type and creates configured instances.
    """
    
    def __init__(self, detector: Optional[CompositeDetector] = None):
        """
        Initialize the unified client factory.
        
        Args:
            detector: Optional custom provider detector. If None, uses default.
        """
        self._detector = detector or CompositeDetector()
        
        # Registry of available client classes
        self._client_registry: Dict[str, Type[LLMClient]] = {
            ProviderType.OPENAI.value: OpenAIClient,
            ProviderType.OLLAMA.value: OllamaClient,
        }
        
        # Cache for created clients (optional optimization)
        self._client_cache: Dict[str, LLMClient] = {}
        self._cache_enabled = False
    
    def create_client(self, config: GeneratorConfig) -> LLMClient:
        """
        Create an LLM client based on configuration.
        
        Args:
            config: Generator configuration
            
        Returns:
            Configured LLM client instance
            
        Raises:
            ConfigurationError: If configuration is invalid
            ProviderError: If provider cannot be determined or is not supported
        """
        # Validate configuration first
        validation_errors = validate_config(config)
        if validation_errors:
            raise ConfigurationError(
                f"Configuration validation failed: {'; '.join(validation_errors)}",
                details={"validation_errors": validation_errors}
            )
        
        # Determine provider
        provider = self._determine_provider(config)
        
        # Check if provider is supported
        if provider not in self._client_registry:
            supported_providers = list(self._client_registry.keys())
            raise ProviderError(
                f"Unsupported provider: {provider}. Supported providers: {supported_providers}",
                provider=provider,
                model=config.model
            )
        
        # Check cache if enabled
        if self._cache_enabled:
            cache_key = self._generate_cache_key(config, provider)
            if cache_key in self._client_cache:
                logger.debug(f"Returning cached client for {provider}:{config.model}")
                return self._client_cache[cache_key]
        
        # Create new client instance
        try:
            client_class = self._client_registry[provider]
            client = client_class(config)
            
            logger.info(f"Created {provider} client for model {config.model}")
            
            # Cache the client if caching is enabled
            if self._cache_enabled:
                cache_key = self._generate_cache_key(config, provider)
                self._client_cache[cache_key] = client
            
            return client
            
        except Exception as e:
            raise ProviderError(
                f"Failed to create {provider} client: {str(e)}",
                provider=provider,
                model=config.model
            ) from e
    
    def get_supported_providers(self) -> List[str]:
        """
        Get list of providers this factory can create clients for.
        
        Returns:
            List of supported provider names
        """
        return list(self._client_registry.keys())
    
    def validate_provider_config(self, provider: str, config: Dict[str, Any]) -> List[str]:
        """
        Validate provider-specific configuration.
        
        Args:
            provider: Provider name
            config: Configuration to validate
            
        Returns:
            List of validation error messages
        """
        if provider not in self._client_registry:
            return [f"Unsupported provider: {provider}"]
        
        try:
            # Create a temporary config object for validation
            temp_config = GeneratorConfig(
                model=config.get("model", "temp-model"),
                provider=provider,
                api_key=config.get("api_key"),
                base_url=config.get("base_url"),
                timeout=config.get("timeout", 30.0),
                max_retries=config.get("max_retries", 3),
                retry_delay=config.get("retry_delay", 1.0),
                generation_kwargs=config.get("generation_kwargs", {})
            )
            
            # Create temporary client instance for validation
            client_class = self._client_registry[provider]
            temp_client = client_class(temp_config)
            
            return temp_client.validate_config()
            
        except Exception as e:
            return [f"Configuration validation failed: {str(e)}"]
    
    def register_client(self, provider: str, client_class: Type[LLMClient]) -> None:
        """
        Register a new client class for a provider.
        
        Args:
            provider: Provider name
            client_class: Client class to register
        """
        if not issubclass(client_class, LLMClient):
            raise ValueError(f"Client class must inherit from LLMClient")
        
        self._client_registry[provider] = client_class
        logger.info(f"Registered client class for provider: {provider}")
    
    def unregister_client(self, provider: str) -> bool:
        """
        Unregister a client class for a provider.
        
        Args:
            provider: Provider name to unregister
            
        Returns:
            True if provider was unregistered, False if not found
        """
        if provider in self._client_registry:
            del self._client_registry[provider]
            logger.info(f"Unregistered client class for provider: {provider}")
            return True
        return False
    
    def enable_caching(self, enabled: bool = True) -> None:
        """
        Enable or disable client caching.
        
        Args:
            enabled: Whether to enable caching
        """
        self._cache_enabled = enabled
        if not enabled:
            self._client_cache.clear()
        logger.info(f"Client caching {'enabled' if enabled else 'disabled'}")
    
    def clear_cache(self) -> None:
        """Clear the client cache."""
        self._client_cache.clear()
        logger.info("Client cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            "enabled": self._cache_enabled,
            "size": len(self._client_cache),
            "keys": list(self._client_cache.keys()) if self._cache_enabled else []
        }
    
    def _determine_provider(self, config: GeneratorConfig) -> str:
        """
        Determine the provider for a given configuration.
        
        Args:
            config: Generator configuration
            
        Returns:
            Provider name
            
        Raises:
            ProviderError: If provider cannot be determined
        """
        # First check if provider is explicitly specified
        if config.provider:
            provider = config.provider.lower()
            if provider in self._client_registry:
                confidence = get_provider_confidence(config.model, provider)
                logger.debug(f"Using explicit provider {provider} with confidence {confidence}")
                return provider
            else:
                raise ProviderError(
                    f"Explicitly specified provider '{provider}' is not supported",
                    provider=provider,
                    model=config.model
                )
        
        # Use automatic detection
        config_dict = {
            "api_key": config.api_key,
            "base_url": config.base_url,
            "timeout": config.timeout,
            "max_retries": config.max_retries,
            "retry_delay": config.retry_delay,
            "generation_kwargs": config.generation_kwargs
        }
        
        detected_provider = self._detector.detect_provider(config.model, config_dict)
        
        if not detected_provider:
            raise ProviderError(
                f"Could not determine provider for model '{config.model}'. "
                f"Please specify provider explicitly or use a recognized model name.",
                model=config.model
            )
        
        confidence = self._detector.get_confidence_score(config.model, detected_provider)
        logger.info(f"Auto-detected provider {detected_provider} for model {config.model} "
                   f"with confidence {confidence:.2f}")
        
        return detected_provider
    
    def _generate_cache_key(self, config: GeneratorConfig, provider: str) -> str:
        """
        Generate a cache key for a configuration and provider.
        
        Args:
            config: Generator configuration
            provider: Provider name
            
        Returns:
            Cache key string
        """
        # Create a simple cache key based on key configuration parameters
        key_parts = [
            provider,
            config.model,
            config.api_key or "no-key",
            config.base_url or "default-url",
            str(config.timeout),
            str(config.max_retries)
        ]
        return ":".join(key_parts)


class ProviderRegistry:
    """
    Registry for managing available providers and their capabilities.
    
    This class provides a centralized way to manage provider information,
    capabilities, and metadata.
    """
    
    def __init__(self):
        """Initialize the provider registry."""
        self._providers: Dict[str, Dict[str, Any]] = {}
        self._initialize_default_providers()
    
    def register_provider(
        self,
        name: str,
        client_class: Type[LLMClient],
        capabilities: List[str],
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a provider with the registry.
        
        Args:
            name: Provider name
            client_class: Client class for the provider
            capabilities: List of supported capabilities
            description: Provider description
            metadata: Additional provider metadata
        """
        self._providers[name] = {
            "client_class": client_class,
            "capabilities": capabilities,
            "description": description,
            "metadata": metadata or {},
            "registered_at": logger.info(f"Registered provider: {name}")
        }
    
    def unregister_provider(self, name: str) -> bool:
        """
        Unregister a provider from the registry.
        
        Args:
            name: Provider name to unregister
            
        Returns:
            True if provider was unregistered, False if not found
        """
        if name in self._providers:
            del self._providers[name]
            logger.info(f"Unregistered provider: {name}")
            return True
        return False
    
    def get_provider_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a provider.
        
        Args:
            name: Provider name
            
        Returns:
            Provider information dictionary or None if not found
        """
        return self._providers.get(name)
    
    def list_providers(self) -> List[str]:
        """
        Get list of registered provider names.
        
        Returns:
            List of provider names
        """
        return list(self._providers.keys())
    
    def get_providers_by_capability(self, capability: str) -> List[str]:
        """
        Get providers that support a specific capability.
        
        Args:
            capability: Capability to search for
            
        Returns:
            List of provider names that support the capability
        """
        matching_providers = []
        for name, info in self._providers.items():
            if capability in info.get("capabilities", []):
                matching_providers.append(name)
        return matching_providers
    
    def get_all_capabilities(self) -> List[str]:
        """
        Get all capabilities supported by any provider.
        
        Returns:
            List of all unique capabilities
        """
        all_capabilities = set()
        for info in self._providers.values():
            all_capabilities.update(info.get("capabilities", []))
        return list(all_capabilities)
    
    def _initialize_default_providers(self) -> None:
        """Initialize the registry with default providers."""
        # Register OpenAI provider
        self.register_provider(
            name=ProviderType.OPENAI.value,
            client_class=OpenAIClient,
            capabilities=["text_generation", "chat_completion", "streaming", "function_calling"],
            description="OpenAI API provider supporting GPT models",
            metadata={
                "api_base": "https://api.openai.com/v1",
                "requires_api_key": True,
                "supports_custom_base_url": True
            }
        )
        
        # Register Ollama provider
        self.register_provider(
            name=ProviderType.OLLAMA.value,
            client_class=OllamaClient,
            capabilities=["text_generation", "streaming"],
            description="Ollama local deployment provider",
            metadata={
                "api_base": "http://localhost:11434",
                "requires_api_key": False,
                "supports_model_management": True
            }
        )


# Global instances
default_factory = UnifiedClientFactory()
provider_registry = ProviderRegistry()


def create_client(config: GeneratorConfig) -> LLMClient:
    """
    Convenience function to create a client using the default factory.
    
    Args:
        config: Generator configuration
        
    Returns:
        Configured LLM client instance
    """
    return default_factory.create_client(config)


def get_supported_providers() -> List[str]:
    """
    Convenience function to get supported providers.
    
    Returns:
        List of supported provider names
    """
    return default_factory.get_supported_providers()


def register_custom_client(provider: str, client_class: Type[LLMClient]) -> None:
    """
    Convenience function to register a custom client.
    
    Args:
        provider: Provider name
        client_class: Client class to register
    """
    default_factory.register_client(provider, client_class)
    
    # Also register with the provider registry if it's a proper LLMClient
    if hasattr(client_class, 'get_supported_capabilities'):
        try:
            # Create a temporary instance to get capabilities
            temp_config = GeneratorConfig(model="temp")
            temp_client = client_class(temp_config)
            capabilities = [cap.value for cap in temp_client.get_supported_capabilities()]
            
            provider_registry.register_provider(
                name=provider,
                client_class=client_class,
                capabilities=capabilities,
                description=f"Custom {provider} provider"
            )
        except Exception:
            # If we can't get capabilities, register with basic info
            provider_registry.register_provider(
                name=provider,
                client_class=client_class,
                capabilities=["text_generation"],
                description=f"Custom {provider} provider"
            )