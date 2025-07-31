"""
OpenAI client adapter for the unified Haystack generator.

This module provides a concrete implementation of the LLMClient interface
for OpenAI's API, supporting both synchronous and asynchronous operations.
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
    ValidationError, ServiceUnavailableError, ContentFilterError,
    ModelNotFoundError
)
from .types import (
    ProviderStatus, ModelCapability, OPENAI_DEFAULT_BASE_URL,
    OPENAI_DEFAULT_MODEL, HTTP_STATUS_TO_ERROR_CODE
)


class OpenAIClient(LLMClient, StreamingClient, ConfigurableClient):
    """
    OpenAI API client adapter.
    
    This client implements the LLMClient interface for OpenAI's API,
    providing support for text generation, streaming, and configuration updates.
    """
    
    def __init__(self, config: GeneratorConfig):
        """
        Initialize the OpenAI client.
        
        Args:
            config: Generator configuration with OpenAI-specific settings
        """
        super().__init__(config)
        
        # OpenAI-specific configuration
        self._api_key = config.api_key
        self._base_url = config.base_url or OPENAI_DEFAULT_BASE_URL
        self._model = config.model or OPENAI_DEFAULT_MODEL
        
        # Ensure base URL ends with /
        if not self._base_url.endswith('/'):
            self._base_url += '/'
        
        # HTTP session for connection pooling
        self._session: Optional[aiohttp.ClientSession] = None
        self._sync_session: Optional[requests.Session] = None
        
        # Supported capabilities
        self._capabilities = [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.CHAT_COMPLETION,
            ModelCapability.STREAMING,
        ]
        
        # Add function calling support for newer models
        if any(model in self._model.lower() for model in ['gpt-4', 'gpt-3.5-turbo']):
            self._capabilities.append(ModelCapability.FUNCTION_CALLING)
    
    async def generate(
        self,
        prompt: str,
        generation_kwargs: Optional[Dict[str, Any]] = None
    ) -> GenerationResponse:
        """
        Generate text using OpenAI's API.
        
        Args:
            prompt: Input prompt for generation
            generation_kwargs: Additional generation parameters
            
        Returns:
            GenerationResponse containing the generated text and metadata
            
        Raises:
            ValidationError: If prompt or parameters are invalid
            APIError: If API request fails
            AuthenticationError: If API key is invalid
            RateLimitError: If rate limit is exceeded
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
                endpoint="chat/completions",
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
                endpoint="chat/completions",
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
        self._api_key = new_config.api_key
        self._base_url = new_config.base_url or OPENAI_DEFAULT_BASE_URL
        self._model = new_config.model or OPENAI_DEFAULT_MODEL
        
        # Ensure base URL ends with /
        if not self._base_url.endswith('/'):
            self._base_url += '/'
        
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
        
        if not self._api_key:
            errors.append("API key is required for OpenAI client")
        elif not self._api_key.startswith(('sk-', 'pk-')):
            errors.append("OpenAI API key should start with 'sk-' or 'pk-'")
        
        if not self._model:
            errors.append("Model name is required")
        
        if not self._base_url:
            errors.append("Base URL is required")
        elif not self._base_url.startswith(('http://', 'https://')):
            errors.append("Base URL must use HTTP or HTTPS")
        
        return errors
    
    def get_provider_name(self) -> str:
        """Get the provider name."""
        return ProviderType.OPENAI.value
    
    async def health_check(self) -> ProviderStatus:
        """
        Check the health status of the OpenAI API.
        
        Returns:
            Current health status
        """
        try:
            # Make a simple request to check API availability
            await self._make_request(
                endpoint="models",
                method="GET"
            )
            return ProviderStatus.HEALTHY
        except AuthenticationError:
            return ProviderStatus.UNAVAILABLE
        except (APIError, TimeoutError):
            return ProviderStatus.DEGRADED
        except Exception:
            return ProviderStatus.UNKNOWN
    
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
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AuditLuma-UnifiedGenerator/1.0"
            }
        )
        
        self._sync_session = requests.Session()
        self._sync_session.headers.update({
            "Authorization": f"Bearer {self._api_key}",
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
    
    def _prepare_request(
        self,
        prompt: str,
        generation_kwargs: Dict[str, Any],
        stream: bool = False
    ) -> Dict[str, Any]:
        """
        Prepare request data for OpenAI API.
        
        Args:
            prompt: Input prompt
            generation_kwargs: Generation parameters
            stream: Whether to enable streaming
            
        Returns:
            Request data dictionary
        """
        # Convert prompt to messages format
        messages = [{"role": "user", "content": prompt}]
        
        # Base request data
        request_data = {
            "model": self._model,
            "messages": messages,
            "stream": stream
        }
        
        # Add generation parameters
        param_mapping = {
            "temperature": "temperature",
            "max_tokens": "max_tokens",
            "top_p": "top_p",
            "frequency_penalty": "frequency_penalty",
            "presence_penalty": "presence_penalty",
            "stop": "stop"
        }
        
        for param, api_param in param_mapping.items():
            if param in generation_kwargs:
                request_data[api_param] = generation_kwargs[param]
        
        return request_data
    
    async def _make_request(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        method: str = "POST"
    ) -> Dict[str, Any]:
        """
        Make HTTP request to OpenAI API.
        
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
        Make streaming HTTP request to OpenAI API.
        
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
                    error_data = await response.json()
                    raise self._create_api_error(response.status, error_data)
                
                async for line in response.content:
                    line = line.decode('utf-8').strip()
                    
                    if line.startswith('data: '):
                        data_str = line[6:]  # Remove 'data: ' prefix
                        
                        if data_str == '[DONE]':
                            break
                        
                        try:
                            chunk_data = json.loads(data_str)
                            if 'choices' in chunk_data and chunk_data['choices']:
                                delta = chunk_data['choices'][0].get('delta', {})
                                if 'content' in delta:
                                    yield delta['content']
                        except json.JSONDecodeError:
                            continue  # Skip invalid JSON chunks
                            
        except asyncio.TimeoutError:
            raise TimeoutError("Streaming request timed out")
        except aiohttp.ClientError as e:
            raise APIError(f"HTTP client error: {str(e)}")
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Dict[str, Any]:
        """
        Handle HTTP response from OpenAI API.
        
        Args:
            response: HTTP response
            
        Returns:
            Parsed response data
            
        Raises:
            APIError: If response indicates an error
        """
        response_data = await response.json()
        
        if response.status == 200:
            return response_data
        else:
            raise self._create_api_error(response.status, response_data)
    
    def _create_api_error(self, status_code: int, response_data: Dict[str, Any]) -> Exception:
        """
        Create appropriate exception based on API response.
        
        Args:
            status_code: HTTP status code
            response_data: Response data from API
            
        Returns:
            Appropriate exception instance
        """
        error_info = response_data.get('error', {})
        error_message = error_info.get('message', f'API request failed with status {status_code}')
        error_type = error_info.get('type', 'unknown')
        
        # Map status codes to exceptions
        if status_code == 401:
            return AuthenticationError(
                error_message,
                status_code=status_code,
                response_body=json.dumps(response_data),
                provider=self.get_provider_name()
            )
        elif status_code == 429:
            return RateLimitError(
                error_message,
                status_code=status_code,
                response_body=json.dumps(response_data),
                provider=self.get_provider_name()
            )
        elif status_code == 404:
            return ModelNotFoundError(
                error_message,
                model=self._model,
                provider=self.get_provider_name()
            )
        elif status_code >= 500:
            return ServiceUnavailableError(
                error_message,
                status_code=status_code,
                response_body=json.dumps(response_data),
                provider=self.get_provider_name()
            )
        elif error_type == 'content_filter':
            return ContentFilterError(
                error_message,
                filter_reason=error_info.get('param'),
                status_code=status_code,
                provider=self.get_provider_name()
            )
        else:
            return APIError(
                error_message,
                status_code=status_code,
                response_body=json.dumps(response_data),
                provider=self.get_provider_name()
            )
    
    def _parse_response(self, response_data: Dict[str, Any]) -> GenerationResponse:
        """
        Parse OpenAI API response into GenerationResponse.
        
        Args:
            response_data: Raw API response data
            
        Returns:
            Parsed GenerationResponse
        """
        choices = response_data.get('choices', [])
        if not choices:
            raise APIError("No choices in API response")
        
        choice = choices[0]
        message = choice.get('message', {})
        content = message.get('content', '')
        finish_reason = choice.get('finish_reason')
        
        # Extract usage information
        usage = response_data.get('usage', {})
        
        # Create metadata
        metadata = {
            'model': response_data.get('model', self._model),
            'created': response_data.get('created'),
            'id': response_data.get('id'),
            'object': response_data.get('object'),
            'finish_reason': finish_reason
        }
        
        return GenerationResponse(
            content=content,
            model=self._model,
            provider=self.get_provider_name(),
            usage=usage,
            finish_reason=finish_reason,
            metadata=metadata
        )