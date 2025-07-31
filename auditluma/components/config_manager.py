"""
Configuration management system for the unified Haystack generator.

This module provides comprehensive configuration management including
YAML file parsing, environment variable substitution, validation,
and hot reloading capabilities.
"""

import os
import yaml
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime
import threading
import time
import logging

from .models import GeneratorConfig, ProviderType
from .exceptions import ConfigurationError
from .validation import validate_config

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """
    Comprehensive configuration manager for the unified generator.
    
    This manager supports YAML configuration files, environment variable
    substitution, validation, and hot reloading capabilities.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, uses default locations.
        """
        self._config_path = config_path
        self._config_data: Dict[str, Any] = {}
        self._last_modified: Optional[float] = None
        self._watchers: List[Callable[[Dict[str, Any]], None]] = []
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_enabled = False
        self._lock = threading.RLock()
        
        # Default configuration compatible with existing config.yaml structure
        self._default_config = {
            "agent": {
                "default_provider": "ollama"
            },
            "openai": {
                "model": "gpt-4-turbo-preview",
                "api_key": "${OPENAI_API_KEY}",
                "base_url": "https://api.openai.com/v1",
                "max_tokens": 8000,
                "temperature": 0.1
            },
            "ollama": {
                "model": "deepseek-r1:1.5b",
                "api_key": "",
                "base_url": "http://localhost:11434/api",
                "max_tokens": 8000,
                "temperature": 0.1
            },
            "hierarchical_rag_models": {
                "enabled": True,
                "haystack": {
                    "orchestrator_type": "ai",
                    "default_model": "qwen3:32b@ollama"
                }
            }
        }
        
        # Load initial configuration
        self._load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file and environment variables.
        
        Returns:
            Complete configuration dictionary
        """
        with self._lock:
            return self._load_config()
    
    def get_provider_config(self, provider: str) -> Dict[str, Any]:
        """
        Get configuration for a specific provider.
        
        Args:
            provider: Provider name
            
        Returns:
            Provider-specific configuration
        """
        with self._lock:
            # Support both new unified structure and existing config.yaml structure
            if "unified_generator" in self._config_data:
                providers_config = self._config_data["unified_generator"].get("providers", {})
                return providers_config.get(provider, {})
            else:
                # Use existing config.yaml structure where providers are at top level
                return self._config_data.get(provider, {})
    
    def get_model_config(self, model_spec: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for a specific model specification.
        
        Args:
            model_spec: Model specification (e.g., "gpt-4@openai")
            
        Returns:
            Model-specific configuration or None if not found
        """
        with self._lock:
            # Check unified_generator structure first
            if "unified_generator" in self._config_data:
                model_mapping = self._config_data["unified_generator"].get("model_mapping", {})
                if model_spec in model_mapping:
                    return model_mapping[model_spec]
            
            # Check hierarchical_rag_models for model specifications
            hierarchical_config = self._config_data.get("hierarchical_rag_models", {})
            if hierarchical_config.get("enabled"):
                # Check haystack task models
                haystack_config = hierarchical_config.get("haystack", {})
                task_models = haystack_config.get("task_models", {})
                
                # Check if model_spec matches any task model
                for task, task_model in task_models.items():
                    if task_model == model_spec:
                        return self._parse_model_spec(model_spec)
                
                # Check default model
                default_model = haystack_config.get("default_model")
                if default_model == model_spec:
                    return self._parse_model_spec(model_spec)
            
            # Try to parse model_spec directly
            return self._parse_model_spec(model_spec)
    
    def create_generator_config(
        self,
        model: str,
        provider: Optional[str] = None,
        **overrides
    ) -> GeneratorConfig:
        """
        Create a GeneratorConfig from the managed configuration.
        
        Args:
            model: Model name
            provider: Optional provider name
            **overrides: Configuration overrides
            
        Returns:
            Configured GeneratorConfig instance
        """
        with self._lock:
            # Get default provider if not specified
            if not provider:
                provider = self._get_default_provider()
            
            # Start with default values, checking both config structures
            config_dict = {
                "model": model,
                "provider": provider,
                "timeout": self._get_timeout_config(),
                "max_retries": self._get_max_retries_config(),
                "retry_delay": self._get_retry_delay_config(),
                "generation_kwargs": {}
            }
            
            # Check for model-specific configuration
            model_spec = f"{model}@{provider}" if provider else model
            model_config = self.get_model_config(model_spec)
            if model_config:
                config_dict.update(model_config)
                # Update model and provider from mapping if specified
                if "model" in model_config:
                    config_dict["model"] = model_config["model"]
                if "provider" in model_config:
                    config_dict["provider"] = model_config["provider"]
            
            # Get provider-specific configuration
            effective_provider = config_dict.get("provider") or provider
            if effective_provider:
                provider_config = self.get_provider_config(effective_provider)
                # Merge provider config, mapping config.yaml fields to GeneratorConfig fields
                self._merge_provider_config(config_dict, provider_config)
            
            # Apply overrides
            config_dict.update(overrides)
            
            # Create and return GeneratorConfig
            return GeneratorConfig(**config_dict)
    
    def validate_config(self) -> List[str]:
        """
        Validate the current configuration.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        with self._lock:
            # Check if using unified_generator structure or existing config.yaml structure
            if "unified_generator" in self._config_data:
                errors.extend(self._validate_unified_generator_config())
            else:
                errors.extend(self._validate_existing_config_structure())
        
        return errors
    
    def _validate_unified_generator_config(self) -> List[str]:
        """Validate unified generator configuration structure."""
        errors = []
        config = self._config_data.get("unified_generator", {})
        
        # Validate basic structure
        if not isinstance(config, dict):
            errors.append("unified_generator configuration must be a dictionary")
            return errors
        
        # Validate timeout
        timeout = config.get("timeout", 30.0)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            errors.append("timeout must be a positive number")
        
        # Validate max_retries
        max_retries = config.get("max_retries", 3)
        if not isinstance(max_retries, int) or max_retries < 0:
            errors.append("max_retries must be a non-negative integer")
        
        # Validate retry_delay
        retry_delay = config.get("retry_delay", 1.0)
        if not isinstance(retry_delay, (int, float)) or retry_delay < 0:
            errors.append("retry_delay must be a non-negative number")
        
        # Validate providers configuration
        providers = config.get("providers", {})
        if not isinstance(providers, dict):
            errors.append("providers configuration must be a dictionary")
        else:
            for provider_name, provider_config in providers.items():
                if not isinstance(provider_config, dict):
                    errors.append(f"Provider '{provider_name}' configuration must be a dictionary")
                    continue
                
                # Validate provider-specific configuration
                if provider_name == "openai":
                    errors.extend(self._validate_openai_config(provider_config))
                elif provider_name == "ollama":
                    errors.extend(self._validate_ollama_config(provider_config))
        
        # Validate model mapping
        model_mapping = config.get("model_mapping", {})
        if not isinstance(model_mapping, dict):
            errors.append("model_mapping must be a dictionary")
        else:
            for model_spec, mapping_config in model_mapping.items():
                if not isinstance(mapping_config, dict):
                    errors.append(f"Model mapping for '{model_spec}' must be a dictionary")
                    continue
                
                if "provider" not in mapping_config:
                    errors.append(f"Model mapping for '{model_spec}' must specify a provider")
                
                if "model" not in mapping_config:
                    errors.append(f"Model mapping for '{model_spec}' must specify a model")
        
        return errors
    
    def _validate_existing_config_structure(self) -> List[str]:
        """Validate existing config.yaml structure."""
        errors = []
        
        # Validate agent configuration
        agent_config = self._config_data.get("agent", {})
        if agent_config and not isinstance(agent_config, dict):
            errors.append("agent configuration must be a dictionary")
        
        # Validate provider configurations
        known_providers = ["openai", "deepseek", "moonshot", "qwen", "zhipu", "baichuan", "ollama", "ollama_emd"]
        for provider in known_providers:
            provider_config = self._config_data.get(provider, {})
            if provider_config:
                if not isinstance(provider_config, dict):
                    errors.append(f"Provider '{provider}' configuration must be a dictionary")
                    continue
                
                # Validate common fields
                if "model" in provider_config and not isinstance(provider_config["model"], str):
                    errors.append(f"Provider '{provider}' model must be a string")
                
                if "base_url" in provider_config and not isinstance(provider_config["base_url"], str):
                    errors.append(f"Provider '{provider}' base_url must be a string")
                
                if "max_tokens" in provider_config:
                    max_tokens = provider_config["max_tokens"]
                    if not isinstance(max_tokens, int) or max_tokens <= 0:
                        errors.append(f"Provider '{provider}' max_tokens must be a positive integer")
                
                if "temperature" in provider_config:
                    temperature = provider_config["temperature"]
                    if not isinstance(temperature, (int, float)) or temperature < 0 or temperature > 2:
                        errors.append(f"Provider '{provider}' temperature must be between 0 and 2")
        
        # Validate hierarchical_rag_models configuration
        hierarchical_config = self._config_data.get("hierarchical_rag_models", {})
        if hierarchical_config:
            if not isinstance(hierarchical_config, dict):
                errors.append("hierarchical_rag_models configuration must be a dictionary")
            else:
                # Validate enabled flag
                enabled = hierarchical_config.get("enabled")
                if enabled is not None and not isinstance(enabled, bool):
                    errors.append("hierarchical_rag_models.enabled must be a boolean")
                
                # Validate haystack configuration
                haystack_config = hierarchical_config.get("haystack", {})
                if haystack_config and not isinstance(haystack_config, dict):
                    errors.append("hierarchical_rag_models.haystack must be a dictionary")
        
        return errors
    
    def reload_config(self) -> bool:
        """
        Reload configuration from file.
        
        Returns:
            True if configuration was reloaded, False if no changes detected
        """
        with self._lock:
            if not self._config_path or not os.path.exists(self._config_path):
                return False
            
            current_mtime = os.path.getmtime(self._config_path)
            if self._last_modified and current_mtime <= self._last_modified:
                return False
            
            try:
                old_config = self._config_data.copy()
                self._load_config()
                
                # Notify watchers if configuration changed
                if self._config_data != old_config:
                    self._notify_watchers()
                
                logger.info(f"Configuration reloaded from {self._config_path}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to reload configuration: {e}")
                return False
    
    def add_config_watcher(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Add a callback to be notified when configuration changes.
        
        Args:
            callback: Function to call when configuration changes
        """
        with self._lock:
            self._watchers.append(callback)
    
    def remove_config_watcher(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """
        Remove a configuration change callback.
        
        Args:
            callback: Callback function to remove
            
        Returns:
            True if callback was removed, False if not found
        """
        with self._lock:
            try:
                self._watchers.remove(callback)
                return True
            except ValueError:
                return False
    
    def start_watching(self, interval: float = 1.0) -> None:
        """
        Start watching the configuration file for changes.
        
        Args:
            interval: Check interval in seconds
        """
        if self._watch_enabled or not self._config_path:
            return
        
        self._watch_enabled = True
        self._watch_thread = threading.Thread(
            target=self._watch_config_file,
            args=(interval,),
            daemon=True
        )
        self._watch_thread.start()
        logger.info(f"Started watching configuration file: {self._config_path}")
    
    def stop_watching(self) -> None:
        """Stop watching the configuration file for changes."""
        self._watch_enabled = False
        if self._watch_thread:
            self._watch_thread.join(timeout=2.0)
            self._watch_thread = None
        logger.info("Stopped watching configuration file")
    
    def get_config_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the current configuration.
        
        Returns:
            Configuration summary
        """
        with self._lock:
            if "unified_generator" in self._config_data:
                # Unified generator structure
                config = self._config_data["unified_generator"]
                providers = list(config.get("providers", {}).keys())
                default_provider = config.get("default_provider", "auto")
                model_mappings = len(config.get("model_mapping", {}))
            else:
                # Existing config.yaml structure
                known_providers = ["openai", "deepseek", "moonshot", "qwen", "zhipu", "baichuan", "ollama", "ollama_emd"]
                providers = [p for p in known_providers if p in self._config_data]
                default_provider = self._get_default_provider()
                
                # Count hierarchical model configurations
                hierarchical_config = self._config_data.get("hierarchical_rag_models", {})
                haystack_config = hierarchical_config.get("haystack", {})
                model_mappings = len(haystack_config.get("task_models", {}))
            
            return {
                "config_path": self._config_path,
                "last_modified": datetime.fromtimestamp(self._last_modified) if self._last_modified else None,
                "providers": providers,
                "default_provider": default_provider,
                "timeout": 30.0,  # Default value for existing config
                "max_retries": 3,  # Default value for existing config
                "model_mappings": model_mappings,
                "watchers": len(self._watchers),
                "watching": self._watch_enabled,
                "hierarchical_rag_enabled": self._config_data.get("hierarchical_rag_models", {}).get("enabled", False)
            }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file and process environment variables."""
        # Start with default configuration
        self._config_data = self._default_config.copy()
        
        # Find configuration file
        config_file = self._find_config_file()
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f) or {}
                
                # Merge with default configuration
                self._deep_merge(self._config_data, file_config)
                
                self._config_path = config_file
                self._last_modified = os.path.getmtime(config_file)
                
                logger.info(f"Loaded configuration from {config_file}")
                
            except Exception as e:
                logger.error(f"Failed to load configuration from {config_file}: {e}")
                raise ConfigurationError(f"Failed to load configuration: {e}")
        
        # Process environment variables
        self._process_environment_variables(self._config_data)
        
        return self._config_data
    
    def _find_config_file(self) -> Optional[str]:
        """Find the configuration file to use."""
        if self._config_path:
            return self._config_path
        
        # Search in common locations, prioritizing existing config.yaml
        search_paths = [
            "config/config.yaml",  # Existing config file
            "config/config.yml",
            "config/unified_generator.yaml",
            "config/unified_generator.yml",
            ".kiro/unified_generator.yaml",
            ".kiro/unified_generator.yml",
            "unified_generator.yaml",
            "unified_generator.yml"
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _process_environment_variables(self, config: Dict[str, Any]) -> None:
        """Process environment variable substitutions in configuration."""
        def substitute_env_vars(obj):
            if isinstance(obj, dict):
                return {k: substitute_env_vars(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute_env_vars(item) for item in obj]
            elif isinstance(obj, str):
                return self._substitute_env_var(obj)
            else:
                return obj
        
        self._config_data = substitute_env_vars(config)
    
    def _substitute_env_var(self, value: str) -> str:
        """Substitute environment variables in a string value."""
        # Pattern to match ${VAR_NAME} or ${VAR_NAME:default_value}
        pattern = r'\$\{([^}:]+)(?::([^}]*))?\}'
        
        def replace_var(match):
            var_name = match.group(1)
            default_value = match.group(2) if match.group(2) is not None else ""
            return os.getenv(var_name, default_value)
        
        return re.sub(pattern, replace_var, value)
    
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Deep merge update dictionary into base dictionary."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _validate_openai_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate OpenAI provider configuration."""
        errors = []
        
        # API key is optional in config (can be provided at runtime)
        api_key = config.get("api_key")
        if api_key and not isinstance(api_key, str):
            errors.append("OpenAI api_key must be a string")
        
        # Base URL validation
        base_url = config.get("base_url")
        if base_url and not isinstance(base_url, str):
            errors.append("OpenAI base_url must be a string")
        elif base_url and not base_url.startswith(("http://", "https://")):
            errors.append("OpenAI base_url must start with http:// or https://")
        
        # Models list validation (for unified structure)
        models = config.get("models", [])
        if models and not isinstance(models, list):
            errors.append("OpenAI models must be a list")
        elif models and not all(isinstance(model, str) for model in models):
            errors.append("All OpenAI models must be strings")
        
        # Model field validation (for existing config structure)
        model = config.get("model")
        if model and not isinstance(model, str):
            errors.append("OpenAI model must be a string")
        
        return errors
    
    def _validate_ollama_config(self, config: Dict[str, Any]) -> List[str]:
        """Validate Ollama provider configuration."""
        errors = []
        
        # Base URL validation
        base_url = config.get("base_url")
        if base_url and not isinstance(base_url, str):
            errors.append("Ollama base_url must be a string")
        elif base_url and not base_url.startswith(("http://", "https://")):
            errors.append("Ollama base_url must start with http:// or https://")
        
        # Models list validation (for unified structure)
        models = config.get("models", [])
        if models and not isinstance(models, list):
            errors.append("Ollama models must be a list")
        elif models and not all(isinstance(model, str) for model in models):
            errors.append("All Ollama models must be strings")
        
        # Model field validation (for existing config structure)
        model = config.get("model")
        if model and not isinstance(model, str):
            errors.append("Ollama model must be a string")
        
        return errors
    
    def _notify_watchers(self) -> None:
        """Notify all registered watchers of configuration changes."""
        for watcher in self._watchers:
            try:
                watcher(self._config_data)
            except Exception as e:
                logger.error(f"Error in configuration watcher: {e}")
    
    def _watch_config_file(self, interval: float) -> None:
        """Watch configuration file for changes in a separate thread."""
        while self._watch_enabled:
            try:
                if self.reload_config():
                    logger.debug("Configuration file changed and reloaded")
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Error watching configuration file: {e}")
                time.sleep(interval)
    
    def _get_default_provider(self) -> str:
        """Get the default provider from configuration."""
        # Check unified_generator structure first
        if "unified_generator" in self._config_data:
            return self._config_data["unified_generator"].get("default_provider", "auto")
        
        # Check agent configuration (existing config.yaml structure)
        agent_config = self._config_data.get("agent", {})
        return agent_config.get("default_provider", "ollama")
    
    def _parse_model_spec(self, model_spec: str) -> Optional[Dict[str, Any]]:
        """
        Parse a model specification like 'model@provider' into configuration.
        
        Args:
            model_spec: Model specification string
            
        Returns:
            Parsed configuration or None
        """
        if "@" in model_spec:
            model, provider = model_spec.split("@", 1)
            return {
                "model": model,
                "provider": provider
            }
        return None
    
    def _merge_provider_config(self, config_dict: Dict[str, Any], provider_config: Dict[str, Any]) -> None:
        """
        Merge provider configuration into the config dictionary.
        
        Args:
            config_dict: Target configuration dictionary
            provider_config: Provider-specific configuration
        """
        # Map config.yaml fields to GeneratorConfig fields
        field_mapping = {
            "api_key": "api_key",
            "base_url": "base_url", 
            "max_tokens": "max_tokens",
            "temperature": "temperature"
        }
        
        for config_key, target_key in field_mapping.items():
            if config_key in provider_config and target_key not in config_dict:
                if target_key in ["max_tokens", "temperature"]:
                    # These go into generation_kwargs
                    config_dict["generation_kwargs"][target_key] = provider_config[config_key]
                else:
                    # These go into the main config
                    config_dict[target_key] = provider_config[config_key]
    
    def _get_timeout_config(self) -> float:
        """Get timeout configuration from either structure."""
        if "unified_generator" in self._config_data:
            return self._config_data["unified_generator"].get("timeout", 30.0)
        return 30.0  # Default for existing config structure
    
    def _get_max_retries_config(self) -> int:
        """Get max_retries configuration from either structure."""
        if "unified_generator" in self._config_data:
            return self._config_data["unified_generator"].get("max_retries", 3)
        return 3  # Default for existing config structure
    
    def _get_retry_delay_config(self) -> float:
        """Get retry_delay configuration from either structure."""
        if "unified_generator" in self._config_data:
            return self._config_data["unified_generator"].get("retry_delay", 1.0)
        return 1.0  # Default for existing config structure


# Global configuration manager instance
_global_config_manager: Optional[ConfigurationManager] = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigurationManager:
    """
    Get the global configuration manager instance.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        ConfigurationManager instance
    """
    global _global_config_manager
    
    if _global_config_manager is None:
        _global_config_manager = ConfigurationManager(config_path)
    
    return _global_config_manager


def create_config_from_manager(
    model: str,
    provider: Optional[str] = None,
    config_manager: Optional[ConfigurationManager] = None,
    **overrides
) -> GeneratorConfig:
    """
    Create a GeneratorConfig using the configuration manager.
    
    Args:
        model: Model name
        provider: Optional provider name
        config_manager: Optional configuration manager instance
        **overrides: Configuration overrides
        
    Returns:
        Configured GeneratorConfig instance
    """
    manager = config_manager or get_config_manager()
    return manager.create_generator_config(model, provider, **overrides)


def validate_managed_config(config_manager: Optional[ConfigurationManager] = None) -> List[str]:
    """
    Validate the managed configuration.
    
    Args:
        config_manager: Optional configuration manager instance
        
    Returns:
        List of validation error messages
    """
    manager = config_manager or get_config_manager()
    return manager.validate_config()