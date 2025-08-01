"""
Haystack Pipeline Builder for UnifiedGenerator

This module provides utilities for building Haystack pipelines that use
the UnifiedGenerator component, with backward compatibility and enhanced
functionality.
"""

import logging
from typing import Any, Dict, List, Optional, Union, Type
from pathlib import Path

try:
    from haystack import Pipeline
    from haystack.core.serialization import default_from_dict, default_to_dict
    HAYSTACK_AVAILABLE = True
except ImportError:
    HAYSTACK_AVAILABLE = False
    
    # Mock Pipeline class for when Haystack is not available
    class Pipeline:
        def __init__(self):
            self.components = {}
            self.connections = []
        
        def add_component(self, name: str, component: Any):
            self.components[name] = component
        
        def connect(self, sender: str, receiver: str, **kwargs):
            self.connections.append((sender, receiver, kwargs))
        
        def run(self, **kwargs):
            return {"result": "mock_result"}

from .unified_generator import UnifiedGenerator, create_unified_generator
from .exceptions import HaystackIntegrationError

logger = logging.getLogger(__name__)


class HaystackPipelineBuilder:
    """
    Builder class for creating Haystack pipelines with UnifiedGenerator components.
    
    This builder provides a fluent interface for constructing pipelines and handles
    backward compatibility with existing Haystack components.
    """
    
    def __init__(self):
        """Initialize the pipeline builder."""
        self.pipeline = Pipeline()
        self._component_counter = 0
        self._generators = {}
        
        if not HAYSTACK_AVAILABLE:
            logger.warning("Haystack is not available. Using mock implementation.")
    
    def add_unified_generator(
        self,
        name: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        provider: Optional[str] = None,
        **kwargs
    ) -> "HaystackPipelineBuilder":
        """
        Add a UnifiedGenerator component to the pipeline.
        
        Args:
            name: Component name (auto-generated if not provided)
            model: Model name
            provider: Provider name (auto-detected if not specified)
            **kwargs: Additional generator configuration
            
        Returns:
            Self for method chaining
        """
        if name is None:
            name = f"unified_generator_{self._component_counter}"
            self._component_counter += 1
        
        try:
            generator = UnifiedGenerator(
                model=model,
                provider=provider,
                **kwargs
            )
            
            self.pipeline.add_component(name, generator)
            self._generators[name] = generator
            
            logger.info(f"Added UnifiedGenerator '{name}' with model '{model}'")
            
        except Exception as e:
            raise HaystackIntegrationError(
                f"Failed to add UnifiedGenerator '{name}': {e}",
                component=name
            ) from e
        
        return self
    
    def add_openai_generator(
        self,
        name: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        api_key: Optional[str] = None,
        **kwargs
    ) -> "HaystackPipelineBuilder":
        """
        Add an OpenAI-configured UnifiedGenerator to the pipeline.
        
        Args:
            name: Component name (auto-generated if not provided)
            model: OpenAI model name
            api_key: OpenAI API key
            **kwargs: Additional generator configuration
            
        Returns:
            Self for method chaining
        """
        return self.add_unified_generator(
            name=name,
            model=model,
            provider="openai",
            api_key=api_key,
            **kwargs
        )
    
    def add_ollama_generator(
        self,
        name: Optional[str] = None,
        model: str = "qwen3:32b",
        base_url: Optional[str] = None,
        **kwargs
    ) -> "HaystackPipelineBuilder":
        """
        Add an Ollama-configured UnifiedGenerator to the pipeline.
        
        Args:
            name: Component name (auto-generated if not provided)
            model: Ollama model name
            base_url: Ollama service URL
            **kwargs: Additional generator configuration
            
        Returns:
            Self for method chaining
        """
        return self.add_unified_generator(
            name=name,
            model=model,
            provider="ollama",
            base_url=base_url,
            **kwargs
        )
    
    def add_component(
        self,
        name: str,
        component: Any
    ) -> "HaystackPipelineBuilder":
        """
        Add any Haystack component to the pipeline.
        
        Args:
            name: Component name
            component: Haystack component instance
            
        Returns:
            Self for method chaining
        """
        try:
            self.pipeline.add_component(name, component)
            logger.info(f"Added component '{name}' of type {type(component).__name__}")
            
        except Exception as e:
            raise HaystackIntegrationError(
                f"Failed to add component '{name}': {e}",
                component=name
            ) from e
        
        return self
    
    def connect(
        self,
        sender: str,
        receiver: str,
        sender_output: str = "replies",
        receiver_input: str = "prompt"
    ) -> "HaystackPipelineBuilder":
        """
        Connect two components in the pipeline.
        
        Args:
            sender: Name of the sending component
            receiver: Name of the receiving component
            sender_output: Output slot of the sender
            receiver_input: Input slot of the receiver
            
        Returns:
            Self for method chaining
        """
        try:
            if HAYSTACK_AVAILABLE:
                self.pipeline.connect(
                    f"{sender}.{sender_output}",
                    f"{receiver}.{receiver_input}"
                )
            else:
                self.pipeline.connect(sender, receiver, 
                                    sender_output=sender_output,
                                    receiver_input=receiver_input)
            
            logger.info(f"Connected {sender}.{sender_output} -> {receiver}.{receiver_input}")
            
        except Exception as e:
            raise HaystackIntegrationError(
                f"Failed to connect {sender} to {receiver}: {e}",
                component=f"{sender}->{receiver}"
            ) from e
        
        return self
    
    def build(self) -> Pipeline:
        """
        Build and return the configured pipeline.
        
        Returns:
            Configured Haystack pipeline
            
        Raises:
            HaystackIntegrationError: If pipeline building fails
        """
        try:
            # Validate pipeline before returning
            self._validate_pipeline()
            
            # Handle different Haystack versions
            if HAYSTACK_AVAILABLE and hasattr(self.pipeline, 'graph'):
                component_count = len(self.pipeline.graph.nodes)
            else:
                components = getattr(self.pipeline, 'components', getattr(self.pipeline, '_components', {}))
                component_count = len(components)
            logger.info(f"Built pipeline with {component_count} components")
            return self.pipeline
            
        except Exception as e:
            raise HaystackIntegrationError(f"Failed to build pipeline: {e}") from e
    
    def _validate_pipeline(self):
        """Validate the pipeline configuration."""
        # Handle different Haystack versions
        if HAYSTACK_AVAILABLE and hasattr(self.pipeline, 'graph'):
            # Real Haystack pipeline uses NetworkX graph
            components = self.pipeline.graph.nodes
            component_count = len(components)
        else:
            # Mock pipeline or older version
            components = getattr(self.pipeline, 'components', getattr(self.pipeline, '_components', {}))
            component_count = len(components)
        
        if component_count == 0:
            raise HaystackIntegrationError("Pipeline has no components")
        
        # Check for UnifiedGenerator components
        generator_count = len(self._generators)
        if generator_count == 0:
            logger.warning("Pipeline has no UnifiedGenerator components")
        else:
            logger.info(f"Pipeline has {generator_count} UnifiedGenerator components")
    
    def get_component_info(self) -> Dict[str, Any]:
        """
        Get information about components in the pipeline.
        
        Returns:
            Dictionary containing component information
        """
        # Handle different Haystack versions
        if HAYSTACK_AVAILABLE and hasattr(self.pipeline, 'graph'):
            # Real Haystack pipeline uses NetworkX graph
            component_names = list(self.pipeline.graph.nodes)
            component_count = len(component_names)
            connections_count = len(self.pipeline.graph.edges)
        else:
            # Mock pipeline or older version
            components = getattr(self.pipeline, 'components', getattr(self.pipeline, '_components', {}))
            component_names = list(components.keys())
            component_count = len(components)
            connections_count = len(getattr(self.pipeline, 'connections', []))
        
        info = {
            "total_components": component_count,
            "unified_generators": len(self._generators),
            "components": {},
            "connections": connections_count
        }
        
        # Add component details
        for name in component_names:
            if HAYSTACK_AVAILABLE and hasattr(self.pipeline, 'get_component'):
                try:
                    component = self.pipeline.get_component(name)
                except:
                    component = None
            else:
                components = getattr(self.pipeline, 'components', {})
                component = components.get(name)
            
            if component:
                component_info = {
                    "type": type(component).__name__,
                    "is_unified_generator": isinstance(component, UnifiedGenerator)
                }
                
                if isinstance(component, UnifiedGenerator):
                    try:
                        component_info.update(component.get_component_info())
                    except:
                        pass
                
                info["components"][name] = component_info
        
        return info


class PipelineSerializer:
    """
    Utility class for serializing and deserializing Haystack pipelines
    that contain UnifiedGenerator components.
    """
    
    @staticmethod
    def save_pipeline(pipeline: Pipeline, path: Union[str, Path]) -> None:
        """
        Save a pipeline to a file.
        
        Args:
            pipeline: Pipeline to save
            path: File path to save to
            
        Raises:
            HaystackIntegrationError: If serialization fails
        """
        try:
            path = Path(path)
            
            if HAYSTACK_AVAILABLE:
                # Use Haystack's built-in serialization
                pipeline_data = pipeline.to_dict()
            else:
                # Use custom serialization for mock pipeline
                # Handle different Haystack versions
                if HAYSTACK_AVAILABLE and hasattr(pipeline, 'graph'):
                    # Real Haystack pipeline - use to_dict method
                    pipeline_data = pipeline.to_dict()
                else:
                    # Mock pipeline
                    components = getattr(pipeline, 'components', getattr(pipeline, '_components', {}))
                    pipeline_data = {
                        "components": {
                            name: component.to_dict() if hasattr(component, 'to_dict') else str(component)
                            for name, component in components.items()
                        },
                        "connections": getattr(pipeline, 'connections', [])
                    }
            
            import json
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(pipeline_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved pipeline to {path}")
            
        except Exception as e:
            raise HaystackIntegrationError(f"Failed to save pipeline: {e}") from e
    
    @staticmethod
    def load_pipeline(path: Union[str, Path]) -> Pipeline:
        """
        Load a pipeline from a file.
        
        Args:
            path: File path to load from
            
        Returns:
            Loaded pipeline
            
        Raises:
            HaystackIntegrationError: If deserialization fails
        """
        try:
            path = Path(path)
            
            import json
            with open(path, 'r', encoding='utf-8') as f:
                pipeline_data = json.load(f)
            
            if HAYSTACK_AVAILABLE:
                # Use Haystack's built-in deserialization
                pipeline = Pipeline.from_dict(pipeline_data)
            else:
                # Use custom deserialization for mock pipeline
                pipeline = Pipeline()
                
                # Reconstruct components
                for name, component_data in pipeline_data.get("components", {}).items():
                    if isinstance(component_data, dict) and "init_parameters" in component_data:
                        # This looks like a UnifiedGenerator
                        component = UnifiedGenerator.from_dict(component_data)
                        pipeline.add_component(name, component)
                    else:
                        logger.warning(f"Skipping unknown component: {name}")
                
                # Reconstruct connections
                for connection in pipeline_data.get("connections", []):
                    if isinstance(connection, (list, tuple)) and len(connection) >= 2:
                        pipeline.connect(connection[0], connection[1])
            
            logger.info(f"Loaded pipeline from {path}")
            return pipeline
            
        except Exception as e:
            raise HaystackIntegrationError(f"Failed to load pipeline: {e}") from e


# Convenience functions

def create_simple_generation_pipeline(
    model: str = "gpt-3.5-turbo",
    provider: Optional[str] = None,
    **kwargs
) -> Pipeline:
    """
    Create a simple pipeline with a single UnifiedGenerator.
    
    Args:
        model: Model name
        provider: Provider name
        **kwargs: Additional generator configuration
        
    Returns:
        Configured pipeline
    """
    builder = HaystackPipelineBuilder()
    builder.add_unified_generator(
        name="generator",
        model=model,
        provider=provider,
        **kwargs
    )
    return builder.build()


def create_multi_provider_pipeline(
    openai_model: str = "gpt-3.5-turbo",
    ollama_model: str = "qwen3:32b",
    **kwargs
) -> Pipeline:
    """
    Create a pipeline with both OpenAI and Ollama generators.
    
    Args:
        openai_model: OpenAI model name
        ollama_model: Ollama model name
        **kwargs: Additional configuration
        
    Returns:
        Configured pipeline with multiple generators
    """
    builder = HaystackPipelineBuilder()
    
    builder.add_openai_generator(
        name="openai_generator",
        model=openai_model,
        **kwargs.get("openai_kwargs", {})
    )
    
    builder.add_ollama_generator(
        name="ollama_generator", 
        model=ollama_model,
        **kwargs.get("ollama_kwargs", {})
    )
    
    return builder.build()


def migrate_legacy_pipeline(legacy_pipeline_data: Dict[str, Any]) -> Pipeline:
    """
    Migrate a legacy pipeline configuration to use UnifiedGenerator.
    
    Args:
        legacy_pipeline_data: Legacy pipeline configuration
        
    Returns:
        Migrated pipeline
        
    Raises:
        HaystackIntegrationError: If migration fails
    """
    try:
        builder = HaystackPipelineBuilder()
        
        # Process legacy components
        for name, component_data in legacy_pipeline_data.get("components", {}).items():
            component_type = component_data.get("type", "")
            
            if "generator" in component_type.lower() or "llm" in component_type.lower():
                # Convert to UnifiedGenerator
                init_params = component_data.get("init_parameters", {})
                model = init_params.get("model", "gpt-3.5-turbo")
                
                builder.add_unified_generator(
                    name=name,
                    model=model,
                    **init_params
                )
                
                logger.info(f"Migrated {component_type} to UnifiedGenerator: {name}")
            else:
                logger.warning(f"Skipping unknown component type: {component_type}")
        
        return builder.build()
        
    except Exception as e:
        raise HaystackIntegrationError(f"Failed to migrate legacy pipeline: {e}") from e