#!/usr/bin/env python3
"""
LLM Client Utility

Provides a unified interface for interacting with various LLM providers
with built-in safety measures and error handling.
"""

import os
import json
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
import openai
import anthropic
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class LLMClient:
    """
    Unified LLM client for interacting with various AI providers.
    
    Supports OpenAI, Anthropic, and local LLM providers with
    built-in safety measures and error handling.
    """
    
    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.logger = logging.getLogger(__name__)
        
        # Initialize provider-specific clients
        self._init_clients()
        
        # Safety settings
        self.safe_mode = os.getenv("SAFE_MODE", "true").lower() == "true"
        self.max_retries = 3
        self.timeout = 30
        
    def _init_clients(self):
        """Initialize provider-specific clients."""
        try:
            if self.provider == "openai":
                api_key = os.getenv("OPENAI_API_KEY")
                if not api_key:
                    raise ValueError("OPENAI_API_KEY not found in environment")
                openai.api_key = api_key
                
            elif self.provider == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY")
                if not api_key:
                    raise ValueError("ANTHROPIC_API_KEY not found in environment")
                self.anthropic_client = anthropic.Anthropic(api_key=api_key)
                
            elif self.provider == "local":
                # For local LLM providers like Ollama
                self.local_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434")
                
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.provider} client: {e}")
            raise
    
    def chat_completion(self, 
                       messages: List[Dict[str, str]], 
                       model: Optional[str] = None,
                       temperature: float = 0.7,
                       max_tokens: int = 1000) -> str:
        """
        Send a chat completion request to the LLM.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            model: Model to use (optional, uses default for provider)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            
        Returns:
            Generated response text
        """
        try:
            # Safety check for educational mode
            if self.safe_mode:
                self._validate_safe_mode(messages)
            
            if self.provider == "openai":
                return self._openai_completion(messages, model, temperature, max_tokens)
            elif self.provider == "anthropic":
                return self._anthropic_completion(messages, model, temperature, max_tokens)
            elif self.provider == "local":
                return self._local_completion(messages, model, temperature, max_tokens)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
                
        except Exception as e:
            self.logger.error(f"Chat completion failed: {e}")
            return f"Error: {str(e)}"
    
    def _openai_completion(self, messages: List[Dict], model: str, temperature: float, max_tokens: int) -> str:
        """Handle OpenAI API completion."""
        try:
            response = openai.ChatCompletion.create(
                model=model or "gpt-3.5-turbo",
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
            
        except Exception as e:
            self.logger.error(f"OpenAI API error: {e}")
            raise
    
    def _anthropic_completion(self, messages: List[Dict], model: str, temperature: float, max_tokens: int) -> str:
        """Handle Anthropic API completion."""
        try:
            # Convert messages to Anthropic format
            prompt = self._convert_to_anthropic_format(messages)
            
            response = self.anthropic_client.messages.create(
                model=model or "claude-3-sonnet-20240229",
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
            
        except Exception as e:
            self.logger.error(f"Anthropic API error: {e}")
            raise
    
    def _local_completion(self, messages: List[Dict], model: str, temperature: float, max_tokens: int) -> str:
        """Handle local LLM completion (e.g., Ollama)."""
        try:
            import requests
            
            # Convert to local API format
            payload = {
                "model": model or "llama2",
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            response = requests.post(
                f"{self.local_url}/v1/chat/completions",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            result = response.json()
            return result["choices"][0]["message"]["content"]
            
        except Exception as e:
            self.logger.error(f"Local LLM API error: {e}")
            raise
    
    def _convert_to_anthropic_format(self, messages: List[Dict]) -> str:
        """Convert OpenAI format messages to Anthropic format."""
        prompt = ""
        for message in messages:
            if message["role"] == "system":
                prompt += f"System: {message['content']}\n\n"
            elif message["role"] == "user":
                prompt += f"Human: {message['content']}\n\n"
            elif message["role"] == "assistant":
                prompt += f"Assistant: {message['content']}\n\n"
        
        return prompt.strip()
    
    def _validate_safe_mode(self, messages: List[Dict]):
        """Validate that requests are safe for educational mode."""
        dangerous_patterns = [
            "real system",
            "production",
            "live data",
            "actual user",
            "real credentials"
        ]
        
        for message in messages:
            content = message.get("content", "").lower()
            for pattern in dangerous_patterns:
                if pattern in content:
                    raise ValueError(f"Potentially dangerous request detected: {pattern}")
    
    def test_connection(self) -> bool:
        """Test the connection to the LLM provider."""
        try:
            test_messages = [{"role": "user", "content": "Hello, this is a test."}]
            response = self.chat_completion(test_messages)
            return len(response) > 0
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def get_available_models(self) -> List[str]:
        """Get list of available models for the provider."""
        if self.provider == "openai":
            try:
                models = openai.Model.list()
                return [model.id for model in models.data]
            except Exception as e:
                self.logger.error(f"Failed to get OpenAI models: {e}")
                return ["gpt-3.5-turbo", "gpt-4"]
        
        elif self.provider == "anthropic":
            return ["claude-3-sonnet-20240229", "claude-3-opus-20240229", "claude-3-haiku-20240307"]
        
        elif self.provider == "local":
            return ["llama2", "mistral", "codellama"]
        
        return []
    
    def get_usage_info(self) -> Dict[str, Any]:
        """Get usage information for the current session."""
        return {
            "provider": self.provider,
            "safe_mode": self.safe_mode,
            "max_retries": self.max_retries,
            "timeout": self.timeout
        } 