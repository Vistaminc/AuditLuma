"""
Provider detection implementations for the unified Haystack generator.

This module provides concrete implementations of provider detection logic
to automatically identify the appropriate LLM provider based on model names
and configuration.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from .base import ProviderDetector
from .models import ProviderType
from .types import is_openai_model, is_ollama_model, extract_provider_from_model


class DefaultProviderDetector(ProviderDetector):
    """
    Default provider detection implementation.
    
    This detector uses pattern matching and heuristics to identify
    the appropriate provider for a given model.
    """
    
    def __init__(self):
        """Initialize the detector with provider patterns."""
        self._openai_patterns = [
            r"^gpt-\d+(\.\d+)?(-turbo)?(-\d+k)?$",
            r"^text-(davinci|curie|babbage|ada)-\d+$",
            r"^(davinci|curie|babbage|ada)$",
            r"^gpt-3\.5-turbo.*$",
            r"^gpt-4.*$",
        ]
        
        self._ollama_patterns = [
            r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+$",  # model:tag format
            r"^(llama|alpaca|vicuna|mistral|codellama|deepseek|qwen|yi).*$",
            r"^[a-zA-Z0-9_-]+$",  # simple model name (lower confidence)
        ]
        
        # Known model prefixes for higher confidence detection
        self._openai_prefixes = ["gpt-", "text-", "davinci", "curie", "babbage", "ada"]
        self._ollama_prefixes = ["llama", "alpaca", "vicuna", "mistral", "codellama", "deepseek", "qwen", "yi"]
    
    def detect_provider(self, model: str, config: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Detect the provider for a given model.
        
        Args:
            model: Model name to analyze
            config: Optional configuration context
            
        Returns:
            Provider name if detected, None if unable to determine
        """
        if not model:
            return None
        
        # First check for explicit provider suffix (model@provider)
        explicit_provider = extract_provider_from_model(model)
        if explicit_provider:
            if explicit_provider in [p.value for p in ProviderType]:
                return explicit_provider
        
        # Clean model name for pattern matching
        clean_model = model.split("@")[0] if "@" in model else model
        
        # Check OpenAI patterns
        if self._matches_openai_patterns(clean_model):
            return ProviderType.OPENAI.value
        
        # Check Ollama patterns
        if self._matches_ollama_patterns(clean_model):
            return ProviderType.OLLAMA.value
        
        # Use configuration hints if available
        if config:
            if config.get("api_key") and not config.get("base_url", "").startswith("http://localhost"):
                return ProviderType.OPENAI.value
            elif config.get("base_url", "").startswith("http://localhost"):
                return ProviderType.OLLAMA.value
        
        return None
    
    def get_supported_providers(self) -> List[str]:
        """
        Get list of providers this detector can identify.
        
        Returns:
            List of supported provider names
        """
        return [ProviderType.OPENAI.value, ProviderType.OLLAMA.value]
    
    def get_confidence_score(self, model: str, provider: str) -> float:
        """
        Get confidence score for a model-provider pairing.
        
        Args:
            model: Model name
            provider: Provider name
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not model or not provider:
            return 0.0
        
        # Explicit provider suffix gives highest confidence
        explicit_provider = extract_provider_from_model(model)
        if explicit_provider == provider:
            return 1.0
        
        clean_model = model.split("@")[0] if "@" in model else model
        
        if provider == ProviderType.OPENAI.value:
            return self._get_openai_confidence(clean_model)
        elif provider == ProviderType.OLLAMA.value:
            return self._get_ollama_confidence(clean_model)
        
        return 0.0
    
    def _matches_openai_patterns(self, model: str) -> bool:
        """Check if model matches OpenAI patterns."""
        for pattern in self._openai_patterns:
            if re.match(pattern, model, re.IGNORECASE):
                return True
        return False
    
    def _matches_ollama_patterns(self, model: str) -> bool:
        """Check if model matches Ollama patterns."""
        for pattern in self._ollama_patterns:
            if re.match(pattern, model):
                return True
        return False
    
    def _get_openai_confidence(self, model: str) -> float:
        """Get confidence score for OpenAI provider."""
        model_lower = model.lower()
        
        # High confidence patterns
        if any(model_lower.startswith(prefix) for prefix in ["gpt-", "text-"]):
            return 0.95
        
        # Medium confidence patterns
        if any(prefix in model_lower for prefix in self._openai_prefixes):
            return 0.7
        
        # Low confidence - generic patterns
        if self._matches_openai_patterns(model):
            return 0.5
        
        return 0.0
    
    def _get_ollama_confidence(self, model: str) -> float:
        """Get confidence score for Ollama provider."""
        model_lower = model.lower()
        
        # High confidence - model:tag format
        if ":" in model and re.match(r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+$", model):
            return 0.95
        
        # High confidence - known model prefixes
        if any(model_lower.startswith(prefix) for prefix in self._ollama_prefixes):
            return 0.9
        
        # Medium confidence - contains known model names
        if any(prefix in model_lower for prefix in self._ollama_prefixes):
            return 0.7
        
        # Low confidence - generic patterns
        if self._matches_ollama_patterns(model):
            return 0.3
        
        return 0.0


class ConfigBasedDetector(ProviderDetector):
    """
    Configuration-based provider detector.
    
    This detector primarily uses configuration parameters to determine
    the appropriate provider, falling back to model name analysis.
    """
    
    def __init__(self):
        """Initialize the configuration-based detector."""
        self._default_detector = DefaultProviderDetector()
    
    def detect_provider(self, model: str, config: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Detect provider based on configuration and model name.
        
        Args:
            model: Model name to analyze
            config: Configuration context (required for this detector)
            
        Returns:
            Provider name if detected, None if unable to determine
        """
        if not config:
            # Fall back to default detection without config
            return self._default_detector.detect_provider(model, config)
        
        # Check for explicit provider in config
        if "provider" in config and config["provider"]:
            provider = config["provider"].lower()
            if provider in [p.value for p in ProviderType]:
                return provider
        
        # Analyze configuration parameters
        has_api_key = bool(config.get("api_key"))
        base_url = config.get("base_url", "")
        
        # OpenAI indicators
        if has_api_key and (
            not base_url or 
            "openai" in base_url.lower() or
            base_url.startswith("https://api.openai.com")
        ):
            return ProviderType.OPENAI.value
        
        # Ollama indicators
        if (
            not has_api_key and 
            base_url and (
                "localhost" in base_url or
                base_url.startswith("http://127.0.0.1") or
                ":11434" in base_url
            )
        ):
            return ProviderType.OLLAMA.value
        
        # Fall back to model name analysis
        return self._default_detector.detect_provider(model, config)
    
    def get_supported_providers(self) -> List[str]:
        """Get list of supported providers."""
        return self._default_detector.get_supported_providers()
    
    def get_confidence_score(self, model: str, provider: str) -> float:
        """Get confidence score for model-provider pairing."""
        # Configuration-based detection has higher base confidence
        base_score = self._default_detector.get_confidence_score(model, provider)
        return min(base_score + 0.1, 1.0)


class CompositeDetector(ProviderDetector):
    """
    Composite detector that combines multiple detection strategies.
    
    This detector uses multiple detection methods and returns the
    result with the highest confidence score.
    """
    
    def __init__(self, detectors: Optional[List[ProviderDetector]] = None):
        """
        Initialize the composite detector.
        
        Args:
            detectors: List of detectors to use. If None, uses default detectors.
        """
        if detectors is None:
            self._detectors = [
                DefaultProviderDetector(),
                ConfigBasedDetector(),
            ]
        else:
            self._detectors = detectors
    
    def detect_provider(self, model: str, config: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Detect provider using multiple strategies.
        
        Args:
            model: Model name to analyze
            config: Optional configuration context
            
        Returns:
            Provider name with highest confidence, None if no detection
        """
        results = []
        
        for detector in self._detectors:
            try:
                provider = detector.detect_provider(model, config)
                if provider:
                    confidence = detector.get_confidence_score(model, provider)
                    results.append((provider, confidence))
            except Exception:
                # Skip detectors that fail
                continue
        
        if not results:
            return None
        
        # Return provider with highest confidence
        results.sort(key=lambda x: x[1], reverse=True)
        return results[0][0]
    
    def get_supported_providers(self) -> List[str]:
        """Get list of all supported providers."""
        providers = set()
        for detector in self._detectors:
            providers.update(detector.get_supported_providers())
        return list(providers)
    
    def get_confidence_score(self, model: str, provider: str) -> float:
        """Get highest confidence score from all detectors."""
        max_confidence = 0.0
        
        for detector in self._detectors:
            try:
                confidence = detector.get_confidence_score(model, provider)
                max_confidence = max(max_confidence, confidence)
            except Exception:
                continue
        
        return max_confidence
    
    def add_detector(self, detector: ProviderDetector) -> None:
        """
        Add a new detector to the composite.
        
        Args:
            detector: Detector to add
        """
        self._detectors.append(detector)
    
    def remove_detector(self, detector_type: type) -> bool:
        """
        Remove a detector by type.
        
        Args:
            detector_type: Type of detector to remove
            
        Returns:
            True if detector was removed, False if not found
        """
        for i, detector in enumerate(self._detectors):
            if isinstance(detector, detector_type):
                del self._detectors[i]
                return True
        return False
    
    def get_detection_results(self, model: str, config: Optional[Dict[str, Any]] = None) -> List[Tuple[str, str, float]]:
        """
        Get detailed detection results from all detectors.
        
        Args:
            model: Model name to analyze
            config: Optional configuration context
            
        Returns:
            List of tuples (detector_name, provider, confidence)
        """
        results = []
        
        for detector in self._detectors:
            try:
                provider = detector.detect_provider(model, config)
                if provider:
                    confidence = detector.get_confidence_score(model, provider)
                    detector_name = detector.__class__.__name__
                    results.append((detector_name, provider, confidence))
            except Exception as e:
                # Include failed detections for debugging
                detector_name = detector.__class__.__name__
                results.append((detector_name, f"ERROR: {str(e)}", 0.0))
        
        return results


# Default detector instance
default_detector = CompositeDetector()


def detect_provider(model: str, config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Convenience function to detect provider using the default detector.
    
    Args:
        model: Model name to analyze
        config: Optional configuration context
        
    Returns:
        Provider name if detected, None otherwise
    """
    return default_detector.detect_provider(model, config)


def get_provider_confidence(model: str, provider: str) -> float:
    """
    Convenience function to get confidence score using the default detector.
    
    Args:
        model: Model name
        provider: Provider name
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    return default_detector.get_confidence_score(model, provider)


def get_supported_providers() -> List[str]:
    """
    Get list of all supported providers.
    
    Returns:
        List of supported provider names
    """
    return default_detector.get_supported_providers()


def validate_model_provider_pair(model: str, provider: str, min_confidence: float = 0.5) -> bool:
    """
    Validate that a model-provider pair is reasonable.
    
    Args:
        model: Model name
        provider: Provider name
        min_confidence: Minimum confidence threshold
        
    Returns:
        True if the pairing is valid with sufficient confidence
    """
    confidence = get_provider_confidence(model, provider)
    return confidence >= min_confidence