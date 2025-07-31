"""
Ollama client adapter for the unified Haystack generator.

This module provides a concrete implementation of the LLMClient interface
for Ollama's API, supporting both synchronous and asynchronous operations.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, AsyncIterator
import aiohttp
import requests
from urllib.parse import urljoin

from .base import LLMClient, StreamingClient, ConfigurableClient
from .models import GenerationResponse, GeneratorConfig, ProviderType
from .exceptions import (
    APIError, AuthenticationError, RateLimitError, TimeoutError,
    ValidationError, ServiceUnavailableError, ModelNotFoundError
)
from .types import (
    ProviderStatus, ModelCapability, OLLAMA_DEFAULT_BASE_URL,
    OLLAMA_DEFAULT_TIMEOUT
)


class OllamaClient(LLMClient, StreamingClient, ConfigurableClient):
    """
    Ollama API client adapter.
    
    This client implements the LLMClient interface for Ollama's API,
    providing support for text generation, streaming, and configuration updates.
    """
    
    def __init__(self, config: GeneratorConfig):
        """
        Initialize the Ollama client.
        
        Args:
            config: Generator configuration with Ollama-specific settings
        """
        super().__init__(config)
        
        # Ollama-specific configuration
        self._base_url = config.base_url or OLLAMA_DEFAULT_BASE_URL
        self._model = config.model
        self._timeout = config.timeout or OLLAMA_DEFAULT_TIMEOUT
        
        # Ensure base URL ends with /
        if not self._base_url.endswith('/'):
            self._base_url += '/'
        
        # HTTP session for connection pooling
        self._session: Optional[aiohttp.ClientSession] = None
        self._sync_session: Optional[requests.Session] = None
        
        # Supported capabilities
        self._capabilities = [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.STREAMING,
        ]
        
        # Available models cache
        self._available_models: Optional[List[str]] = None
        self._models_cache_time: Optional[datetime] = None
        self._models_cache_ttl = 300  # 5 minutes
    
    async def generate(
        self,
        prompt: str,
        generation_kwargs: Optional[Dict[str, Any]] = None
    ) -> GenerationResponse:
        """
        Generate text using Ollama's API.
        
        Args:
            prompt: Input prompt for generation
            generation_kwargs: Additional generation parameters
            
        Returns:
            GenerationResponse containing the generated text and metadata
            
        Raises:
            ValidationError: If prompt or parameters are invalid
            APIError: If API request fails
            ModelNotFoundError: If model is not available
            TimeoutError: If request times out
        """
        start_time = datetime.now()
        
        try:
            # Validate inputs
            self.validate_prompt(prompt)
            validated_kwargs = self.validate_generation_kwargs(generation_kwargs or {})
            
            # Prepare request
            request_data = self._prepare_request(prompt, validated_kwargs)
            
            # Make API request
            response_data = await self._make_request(
                endpoint="api/generate",
                data=request_data
            )
            
            # Parse response
            generation_response = self._parse_response(response_data)
            
            # Record successful request
            await self._record_request(start_time, success=True)
            
            return generation_response
            
        except Exception as e:
            # Record failed request
            error_type = type(e).__name__
            await self._record_request(start_time, success=False, error_type=error_type)
            raise
    
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
            ValidationError: If prompt or parameters are invalid
            APIError: If API request fails
        """
        start_time = datetime.now()
        
        try:
            # Validate inputs
            self.validate_prompt(prompt)
            validated_kwargs = self.validate_generation_kwargs(generation_kwargs or {})
            
            # Prepare streaming request
            request_data = self._prepare_request(prompt, validated_kwargs, stream=True)
            
            # Make streaming request
            async for chunk in self._make_streaming_request(
                endpoint="api/generate",
                data=request_data
            ):
                yield chunk
            
            # Record successful request
            await self._record_request(start_time, success=True)
            
        except Exception as e:
            # Record failed request
            error_type = type(e).__name__
            await self._record_request(start_time, success=False, error_type=error_type)
            raise
    
    def supports_streaming(self) -> bool:
        """Check if the client supports streaming."""
        return True
    
    async def update_config(self, new_config: GeneratorConfig) -> None:
        """
        Update the client configuration.
        
        Args:
            new_config: New configuration to apply
            
        Raises:
            ValidationError: If new configuration is invalid
        """
        # Validate new configuration
        errors = new_config.validate()
        if errors:
            raise ValidationError(f"Invalid configuration: {'; '.join(errors)}")
        
        # Update configuration
        self.config = new_config
        self._base_url = new_config.base_url or OLLAMA_DEFAULT_BASE_URL
        self._model = new_config.model
        self._timeout = new_config.timeout or OLLAMA_DEFAULT_TIMEOUT
        
        # Ensure base URL ends with /
        if not self._base_url.endswith('/'):
            self._base_url += '/'
        
        # Clear models cache
        self._available_models = None
        self._models_cache_time = None
        
        # Recreate sessions with new configuration
        if self._session:
            await self._session.close()
            self._session = None
        
        if self._sync_session:
            self._sync_session.close()
            self._sync_session = None
    
    def get_current_config(self) -> GeneratorConfig:
        """Get the current configuration."""
        return self.config
    
    def validate_config(self) -> List[str]:
        """
        Validate the client configuration.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        if not self._model:
            errors.append("Model name is required")
        
        if not self._base_url:
            errors.append("Base URL is required")
        elif not self._base_url.startswith(('http://', 'https://')):
            errors.append("Base URL must use HTTP or HTTPS")
        
        if self._timeout <= 0:
            errors.append("Timeout must be positive")
        
        return errors
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return ProviderType.OLLAMA.value
    
    async def health_check(self) -> ProviderStatus:
        """
        Check the health status of the Ollama service.
        
        Returns:
            Current health status
        """
        try:
            # Try to get the list of models to check if service is available
            await self._make_request(
                endpoint="api/tags",
                method="GET"
            )
            return ProviderStatus.HEALTHY
        except (APIError, TimeoutError):
            return ProviderStatus.DEGRADED
        except Exception:
            return ProviderStatus.UNAVAILABLE
    
    def get_supported_capabilities(self) -> List[ModelCapability]:
        """Get the capabilities supported by this client."""
        return self._capabilities.copy()
    
    async def initialize(self) -> None:
        """Initialize the client and establish connections."""
        # Validate configuration
        errors = self.validate_config()
        if errors:
            raise ValidationError(f"Configuration validation failed: {'; '.join(errors)}")
        
        # Create HTTP sessions
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AuditLuma-UnifiedGenerator/1.0"
            }
        )
        
        self._sync_session = requests.Session()
        self._sync_session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "AuditLuma-UnifiedGenerator/1.0"
        })
        
        self._initialized = True
    
    async def cleanup(self) -> None:
        """Clean up resources and close connections."""
        if self._session:
            await self._session.close()
            self._session = None
        
        if self._sync_session:
            self._sync_session.close()
            self._sync_session = None
        
        self._initialized = False
    
    async def get_available_models(self) -> List[str]:
        """
        Get list of available models from Ollama.
        
        Returns:
            List of available model names
        """
        # Check cache
        now = datetime.now()
        if (self._available_models is not None and 
            self._models_cache_time is not None and
            (now - self._models_cache_time).total_seconds() < self._models_cache_ttl):
            return self._available_models
        
        try:
            response_data = await self._make_request(
                endpoint="api/tags",
                method="GET"
            )
            
            models = []
            for model_info in response_data.get("models", []):
                model_name = model_info.get("name", "")
                if model_name:
                    models.append(model_name)
            
            # Update cache
            self._available_models = models
            self._models_cache_time = now
            
            return models
            
        except Exception:
            # Return empty list if we can't get models
            return []
    
    def _prepare_request(
        self,
        prompt: str,
        generation_kwargs: Dict[str, Any],
        stream: bool = False
    ) -> Dict[str, Any]:
        """
        Prepare request data for Ollama API.
        
        Args:
            prompt: Input prompt
            generation_kwargs: Generation parameters
            stream: Whether to enable streaming
            
        Returns:
            Request data dictionary
        """
        # Base request data
        request_data = {
            "model": self._model,
            "prompt": prompt,
            "stream": stream
        }
        
        # Add generation parameters with Ollama-specific mapping
        param_mapping = {
            "temperature": "temperature",
            "top_p": "top_p",
            "top_k": "top_k",
            "repeat_penalty": "repeat_penalty",
            "seed": "seed",
            "stop": "stop"
        }
        
        # Create options dict for Ollama-specific parameters
        options = {}
        for param, api_param in param_mapping.items():
            if param in generation_kwargs:
                options[api_param] = generation_kwargs[param]
        
        # Handle max_tokens -> num_predict mapping
        if "max_tokens" in generation_kwargs:
            options["num_predict"] = generation_kwargs["max_tokens"]
        
        if options:
            request_data["options"] = options
        
        return request_data
    
    async def _make_request(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        method: str = "POST"
    ) -> Dict[str, Any]:
        """
        Make HTTP request to Ollama API.
        
        Args:
            endpoint: API endpoint
            data: Request data
            method: HTTP method
            
        Returns:
            Response data
            
        Raises:
            APIError: If request fails
        """
        if not self._session:
            raise APIError("Client not initialized")
        
        url = urljoin(self._base_url, endpoint)
        
        try:
            if method.upper() == "GET":
                async with self._session.get(url) as response:
                    return await self._handle_response(response)
            else:
                async with self._session.post(url, json=data) as response:
                    return await self._handle_response(response)
                    
        except asyncio.TimeoutError:
            raise TimeoutError("Request timed out")
        except aiohttp.ClientError as e:
            raise APIError(f"HTTP client error: {str(e)}")
    
    async def _make_streaming_request(
        self,
        endpoint: str,
        data: Dict[str, Any]
    ) -> AsyncIterator[str]:
        """
        Make streaming HTTP request to Ollama API.
        
        Args:
            endpoint: API endpoint
            data: Request data
            
        Yields:
            Text chunks from the streaming response
        """
        if not self._session:
            raise APIError("Client not initialized")
        
        url = urljoin(self._base_url, endpoint)
        
        try:
            async with self._session.post(url, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise self._create_api_error(response.status, error_text)
                
                async for line in response.content:
                    line = line.decode('utf-8').strip()
                    
                    if line:
                        try:
                            chunk_data = json.loads(line)
                            
                            # Check for errors in the response
                            if "error" in chunk_data:
                                raise APIError(f"Ollama API error: {chunk_data['error']}")
                            
                            # Extract response text
                            if "response" in chunk_data:
                                response_text = chunk_data["response"]
                                if response_text:
                                    yield response_text
                            
                            # Check if this is the final chunk
                            if chunk_data.get("done", False):
                                break
                                
                        except json.JSONDecodeError:
                            continue  # Skip invalid JSON chunks
                            
        except asyncio.TimeoutError:
            raise TimeoutError("Streaming request timed out")
        except aiohttp.ClientError as e:
            raise APIError(f"HTTP client error: {str(e)}")
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict[str, Any]:
        """
        Handle HTTP response from Ollama API.
        
        Args:
            response: HTTP response
            
        Returns:
            Parsed response data
            
        Raises:
            APIError: If response indicates an error
        """
        if response.status == 200:
            try:
                return await response.json()
            except json.JSONDecodeError:
                # For non-JSON responses, return the text
                text = await response.text()
                return {"response": text}
        else:
            error_text = await response.text()
            raise self._create_api_error(response.status, error_text)
    
    def _create_api_error(self, status_code: int, error_text: str) -> Exception:
        """
        Create appropriate exception based on API response.
        
        Args:
            status_code: HTTP status code
            error_text: Error text from API
            
        Returns:
            Appropriate exception instance
        """
        # Try to parse error as JSON
        try:
            error_data = json.loads(error_text)
            error_message = error_data.get("error", error_text)
        except json.JSONDecodeError:
            error_message = error_text or f"API request failed with status {status_code}"
        
        # Map status codes to exceptions
        if status_code == 404:
            if "model" in error_message.lower():
                return ModelNotFoundError(
                    error_message,
                    model=self._model,
                    provider=self.get_provider_name()
                )
            else:
                return APIError(
                    error_message,
                    status_code=status_code,
                    provider=self.get_provider_name()
                )
        elif status_code >= 500:
            return ServiceUnavailableError(
                error_message,
                status_code=status_code,
                provider=self.get_provider_name()
            )
        else:
            return APIError(
                error_message,
                status_code=status_code,
                provider=self.get_provider_name()
            )
    
    def _parse_response(self, response_data: Dict[str, Any]) -> GenerationResponse:
        """
        Parse Ollama API response into GenerationResponse.
        
        Args:
            response_data: Raw API response data
            
        Returns:
            Parsed GenerationResponse
        """
        # Extract response content
        content = response_data.get("response", "")
        if not content:
            raise APIError("No response content in API response")
        
        # Extract metadata
        model = response_data.get("model", self._model)
        done = response_data.get("done", False)
        
        # Create usage information from available data
        usage = {}
        if "eval_count" in response_data:
            usage["completion_tokens"] = response_data["eval_count"]
        if "prompt_eval_count" in response_data:
            usage["prompt_tokens"] = response_data["prompt_eval_count"]
        if usage:
            usage["total_tokens"] = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)
        
        # Create metadata
        metadata = {
            "model": model,
            "done": done,
            "total_duration": response_data.get("total_duration"),
            "load_duration": response_data.get("load_duration"),
            "prompt_eval_duration": response_data.get("prompt_eval_duration"),
            "eval_duration": response_data.get("eval_duration"),
            "context": response_data.get("context")
        }
        
        # Remove None values from metadata
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        return GenerationResponse(
            content=content,
            model=self._model,
            provider=self.get_provider_name(),
            usage=usage if usage else None,
            finish_reason="stop" if done else None,
            metadata=metadata
        )
    
    def validate_generation_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and normalize generation parameters for Ollama.
        
        Args:
            kwargs: Generation parameters to validate
            
        Returns:
            Validated and normalized parameters
            
        Raises:
            ValidationError: If parameters are invalid
        """
        # Start with base validation
        validated = super().validate_generation_kwargs(kwargs)
        
        # Ollama-specific parameter validation
        if "top_k" in kwargs:
            top_k = kwargs["top_k"]
            if not isinstance(top_k, int) or top_k < 1:
                raise ValidationError(
                    "top_k must be a positive integer",
                    field="top_k",
                    value=top_k
                )
            validated["top_k"] = top_k
        
        if "repeat_penalty" in kwargs:
            repeat_penalty = kwargs["repeat_penalty"]
            if not isinstance(repeat_penalty, (int, float)) or repeat_penalty <= 0:
                raise ValidationError(
                    "repeat_penalty must be a positive number",
                    field="repeat_penalty",
                    value=repeat_penalty
                )
            validated["repeat_penalty"] = float(repeat_penalty)
        
        if "seed" in kwargs:
            seed = kwargs["seed"]
            if not isinstance(seed, int):
                raise ValidationError(
                    "seed must be an integer",
                    field="seed",
                    value=seed
                )
            validated["seed"] = seed
        
        return validated