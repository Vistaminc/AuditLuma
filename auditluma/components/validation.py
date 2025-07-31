"""
Configuration validation utilities for the unified Haystack generator.

This module provides comprehensive validation functions for generator
configurations, ensuring that all settings are valid and compatible.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Union
from .models import GeneratorConfig, ProviderType
from .types import (
    validate_timeout, validate_retry_count, validate_temperature,
    validate_top_p, validate_max_tokens, OPENAI_DEFAULT_BASE_URL,
    OLLAMA_DEFAULT_BASE_URL
)
from .exceptions import ValidationError, ConfigurationError


class ConfigValidator:
    """
    Comprehensive configuration validator for the unified generator.
    
    This class provides methods to validate different aspects of the
    generator configuration and ensure compatibility between settings.
    """
    
    def __init__(self):
        """Initialize the validator with validation rules."""
        self._openai_models = {
            "gpt-4", "gpt-4-turbo", "gpt-4-turbo-preview",
            "gpt-3.5-turbo", "gpt-3.5-turbo-16k",
            "text-davinci-003", "text-davinci-002",
            "text-curie-001", "text-babbage-001", "text-ada-001"
        }
        
        self._required_openai_params = {"api_key"}
        self._optional_openai_params = {
            "base_url", "timeout", "max_retries", "retry_delay",
            "temperature", "max_tokens", "top_p", "frequency_penalty",
            "presence_penalty", "stop", "stream"
        }
        
        self._required_ollama_params: Set[str] = set()
        self._optional_ollama_params = {
            "base_url", "timeout", "max_retries", "retry_delay",
            "temperature", "top_p", "top_k", "repeat_penalty",
            "seed", "stop", "stream"
        }
    
    def validate_config(self, config: GeneratorConfig) -> List[str]:
        """
        Validate a complete generator configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Basic validation
        errors.extend(self._validate_basic_config(config))
        
        # Provider-specific validation
        provider_type = config.get_provider_type()
        if provider_type == ProviderType.OPENAI:
            errors.extend(self._validate_openai_config(config))
        elif provider_type == ProviderType.OLLAMA:
            errors.extend(self._validate_ollama_config(config))
        
        # Generation parameters validation
        errors.extend(self._validate_generation_kwargs(config.generation_kwargs))
        
        # Cross-parameter validation
        errors.extend(self._validate_parameter_compatibility(config))
        
        return errors
    
    def validate_model_name(self, model: str, provider: Optional[str] = None) -> List[str]:
        """
        Validate model name format and availability.
        
        Args:
            model: Model name to validate
            provider: Optional provider context
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not model or not model.strip():
            errors.append("Model name cannot be empty")
            return errors
        
        # Check for invalid characters (allow : for Ollama models)
        if provider == ProviderType.OLLAMA.value:
            # Ollama allows colons for model:tag format
            if re.search(r'[<>"|?*]', model):
                errors.append("Model name contains invalid characters")
        else:
            # Other providers don't allow colons
            if re.search(r'[<>:"|?*]', model):
                errors.append("Model name contains invalid characters")
        
        # Provider-specific model validation
        if provider == ProviderType.OPENAI.value:
            errors.extend(self._validate_openai_model(model))
        elif provider == ProviderType.OLLAMA.value:
            errors.extend(self._validate_ollama_model(model))
        
        return errors
    
    def validate_api_key(self, api_key: str, provider: str) -> List[str]:
        """
        Validate API key format.
        
        Args:
            api_key: API key to validate
            provider: Provider name
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not api_key or not api_key.strip():
            if provider == ProviderType.OPENAI.value:
                errors.append("API key is required for OpenAI provider")
            return errors
        
        # OpenAI API key format validation
        if provider == ProviderType.OPENAI.value:
            if not api_key.startswith(("sk-", "pk-")):
                errors.append("OpenAI API key should start with 'sk-' or 'pk-'")
            
            if len(api_key) < 20:
                errors.append("OpenAI API key appears to be too short")
        
        return errors
    
    def validate_base_url(self, base_url: str, provider: str) -> List[str]:
        """
        Validate base URL format and compatibility.
        
        Args:
            base_url: Base URL to validate
            provider: Provider name
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not base_url:
            return errors  # Base URL is optional
        
        # Basic URL format validation
        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme or not parsed.netloc:
                errors.append("Base URL must be a valid URL with scheme and host")
        except Exception:
            errors.append("Base URL format is invalid")
            return errors
        
        # Provider-specific URL validation
        if provider == ProviderType.OPENAI.value:
            if not base_url.startswith(("http://", "https://")):
                errors.append("OpenAI base URL must use HTTP or HTTPS")
        elif provider == ProviderType.OLLAMA.value:
            if not base_url.startswith(("http://", "https://")):
                errors.append("Ollama base URL must use HTTP or HTTPS")
            # Ollama typically runs on localhost
            if "localhost" not in base_url and "127.0.0.1" not in base_url:
                # This is a warning, not an error
                pass
        
        return errors
    
    def validate_generation_parameters(self, params: Dict[str, Any]) -> List[str]:
        """
        Validate generation parameters.
        
        Args:
            params: Generation parameters to validate
            
        Returns:
            List of validation error messages
        """
        return self._validate_generation_kwargs(params)
    
    def _validate_basic_config(self, config: GeneratorConfig) -> List[str]:
        """Validate basic configuration parameters."""
        errors = []
        
        # Model name validation
        if not config.model or not config.model.strip():
            errors.append("Model name is required")
        
        # Timeout validation
        if not validate_timeout(config.timeout):
            errors.append(f"Timeout must be between 0 and 300 seconds, got {config.timeout}")
        
        # Retry validation
        if not validate_retry_count(config.max_retries):
            errors.append(f"Max retries must be between 0 and 10, got {config.max_retries}")
        
        if config.retry_delay < 0:
            errors.append("Retry delay cannot be negative")
        
        return errors
    
    def _validate_openai_config(self, config: GeneratorConfig) -> List[str]:
        """Validate OpenAI-specific configuration."""
        errors = []
        
        # API key validation
        if not config.api_key:
            errors.append("API key is required for OpenAI provider")
        else:
            errors.extend(self.validate_api_key(config.api_key, ProviderType.OPENAI.value))
        
        # Base URL validation
        if config.base_url:
            errors.extend(self.validate_base_url(config.base_url, ProviderType.OPENAI.value))
        
        # Model validation
        errors.extend(self._validate_openai_model(config.model))
        
        return errors
    
    def _validate_ollama_config(self, config: GeneratorConfig) -> List[str]:
        """Validate Ollama-specific configuration."""
        errors = []
        
        # API key should not be required for Ollama
        if config.api_key:
            # This is a warning, not an error
            pass
        
        # Base URL validation
        if config.base_url:
            errors.extend(self.validate_base_url(config.base_url, ProviderType.OLLAMA.value))
        
        # Model validation
        errors.extend(self._validate_ollama_model(config.model))
        
        return errors
    
    def _validate_openai_model(self, model: str) -> List[str]:
        """Validate OpenAI model name."""
        errors = []
        
        # Remove provider suffix if present
        clean_model = model.split("@")[0] if "@" in model else model
        
        # Check against known models (this is informational, not restrictive)
        if clean_model not in self._openai_models:
            # Check if it matches OpenAI patterns
            openai_patterns = [
                r"^gpt-\d+(\.\d+)?(-turbo)?(-\d+k)?$",
                r"^text-(davinci|curie|babbage|ada)-\d+$",
            ]
            
            if not any(re.match(pattern, clean_model, re.IGNORECASE) for pattern in openai_patterns):
                # This is a warning, not an error - new models may not be in our list
                pass
        
        return errors
    
    def _validate_ollama_model(self, model: str) -> List[str]:
        """Validate Ollama model name."""
        errors = []
        
        # Remove provider suffix if present
        clean_model = model.split("@")[0] if "@" in model else model
        
        # Ollama models can have various formats, so we're lenient
        # Just check for obviously invalid formats
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:')
        if not all(c in allowed_chars for c in clean_model):
            errors.append("Ollama model name contains invalid characters")
        
        return errors
    
    def _validate_generation_kwargs(self, kwargs: Dict[str, Any]) -> List[str]:
        """Validate generation parameters."""
        errors = []
        
        if not kwargs:
            return errors
        
        # Temperature validation
        if "temperature" in kwargs:
            temp = kwargs["temperature"]
            if not isinstance(temp, (int, float)):
                errors.append("Temperature must be a number")
            elif not validate_temperature(temp):
                errors.append("Temperature must be between 0.0 and 2.0")
        
        # Max tokens validation
        if "max_tokens" in kwargs:
            max_tokens = kwargs["max_tokens"]
            if not isinstance(max_tokens, int):
                errors.append("max_tokens must be an integer")
            elif not validate_max_tokens(max_tokens):
                errors.append("max_tokens must be between 1 and 4096")
        
        # Top-p validation
        if "top_p" in kwargs:
            top_p = kwargs["top_p"]
            if not isinstance(top_p, (int, float)):
                errors.append("top_p must be a number")
            elif not validate_top_p(top_p):
                errors.append("top_p must be between 0.0 and 1.0")
        
        # Frequency penalty validation (OpenAI specific)
        if "frequency_penalty" in kwargs:
            penalty = kwargs["frequency_penalty"]
            if not isinstance(penalty, (int, float)):
                errors.append("frequency_penalty must be a number")
            elif not (-2.0 <= penalty <= 2.0):
                errors.append("frequency_penalty must be between -2.0 and 2.0")
        
        # Presence penalty validation (OpenAI specific)
        if "presence_penalty" in kwargs:
            penalty = kwargs["presence_penalty"]
            if not isinstance(penalty, (int, float)):
                errors.append("presence_penalty must be a number")
            elif not (-2.0 <= penalty <= 2.0):
                errors.append("presence_penalty must be between -2.0 and 2.0")
        
        # Stop sequences validation
        if "stop" in kwargs:
            stop = kwargs["stop"]
            if isinstance(stop, str):
                if len(stop) > 100:
                    errors.append("Stop sequence is too long")
            elif isinstance(stop, list):
                if len(stop) > 4:
                    errors.append("Too many stop sequences (maximum 4)")
                for seq in stop:
                    if not isinstance(seq, str):
                        errors.append("Stop sequences must be strings")
                    elif len(seq) > 100:
                        errors.append("Stop sequence is too long")
            else:
                errors.append("Stop must be a string or list of strings")
        
        return errors
    
    def _validate_parameter_compatibility(self, config: GeneratorConfig) -> List[str]:
        """Validate compatibility between different parameters."""
        errors = []
        
        # Check if generation parameters are compatible with provider
        provider_type = config.get_provider_type()
        
        if provider_type == ProviderType.OPENAI:
            # Check for Ollama-specific parameters
            ollama_only_params = {"top_k", "repeat_penalty", "seed"}
            for param in ollama_only_params:
                if param in config.generation_kwargs:
                    errors.append(f"Parameter '{param}' is not supported by OpenAI provider")
        
        elif provider_type == ProviderType.OLLAMA:
            # Check for OpenAI-specific parameters
            openai_only_params = {"frequency_penalty", "presence_penalty"}
            for param in openai_only_params:
                if param in config.generation_kwargs:
                    errors.append(f"Parameter '{param}' is not supported by Ollama provider")
        
        # Check for conflicting parameters
        if "temperature" in config.generation_kwargs and "top_p" in config.generation_kwargs:
            temp = config.generation_kwargs["temperature"]
            top_p = config.generation_kwargs["top_p"]
            if temp == 0 and top_p != 1:
                errors.append("When temperature is 0, top_p should be 1 (deterministic generation)")
        
        return errors


# Default validator instance
default_validator = ConfigValidator()


def validate_config(config: GeneratorConfig) -> List[str]:
    """
    Convenience function to validate configuration using the default validator.
    
    Args:
        config: Configuration to validate
        
    Returns:
        List of validation error messages
    """
    return default_validator.validate_config(config)


def validate_model_name(model: str, provider: Optional[str] = None) -> List[str]:
    """
    Convenience function to validate model name.
    
    Args:
        model: Model name to validate
        provider: Optional provider context
        
    Returns:
        List of validation error messages
    """
    return default_validator.validate_model_name(model, provider)


def validate_generation_parameters(params: Dict[str, Any]) -> List[str]:
    """
    Convenience function to validate generation parameters.
    
    Args:
        params: Generation parameters to validate
        
    Returns:
        List of validation error messages
    """
    return default_validator.validate_generation_parameters(params)


def is_valid_config(config: GeneratorConfig) -> bool:
    """
    Check if a configuration is valid.
    
    Args:
        config: Configuration to check
        
    Returns:
        True if configuration is valid
    """
    errors = validate_config(config)
    return len(errors) == 0


def raise_for_invalid_config(config: GeneratorConfig) -> None:
    """
    Raise ConfigurationError if configuration is invalid.
    
    Args:
        config: Configuration to validate
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    errors = validate_config(config)
    if errors:
        raise ConfigurationError(
            f"Configuration validation failed: {'; '.join(errors)}",
            details={"validation_errors": errors}
        )