import logging
import os
from functools import lru_cache
from pathlib import Path

import yaml
from langchain_core.language_models.chat_models import BaseChatModel

logger = logging.getLogger(__name__)

_config: dict | None = None


def _load_config() -> dict:
    """Load configuration from config.yaml."""
    global _config
    if _config is not None:
        return _config

    config_path = Path(__file__).parent.parent / "config.yaml"
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
        _config = yaml.safe_load(f)
    return _config


def _resolve_env_var(value: str) -> str:
    """Resolve ${ENV_VAR} references in config values."""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        env_name = value[2:-1]
        resolved = os.getenv(env_name, "")
        if not resolved:
            logger.warning(f"Environment variable {env_name} is not set")
        return resolved
    return value


def _create_anthropic_model(model: str, api_key: str, **kwargs) -> BaseChatModel:
    from langchain_anthropic import ChatAnthropic

    return ChatAnthropic(
        model=model,
        api_key=api_key,
        temperature=0,
    )


def _create_openai_model(
    model: str, api_key: str, base_url: str | None = None, **kwargs
) -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    params = {"model": model, "temperature": 0, "api_key": api_key}
    if base_url:
        params["base_url"] = base_url
    return ChatOpenAI(**params)


def _create_ollama_model(
    model: str, base_url: str = "http://localhost:11434", **kwargs
) -> BaseChatModel:
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=model,
        base_url=base_url,
        temperature=0,
    )


_PROVIDER_FACTORIES = {
    "anthropic": _create_anthropic_model,
    "openai": _create_openai_model,
    "deepseek": _create_openai_model,  # DeepSeek uses OpenAI-compatible API
    "ollama": _create_ollama_model,
}


def get_llm(agent_name: str) -> BaseChatModel:
    """
    Get the configured LLM for a specific agent.

    Looks up the agent's provider/model in config.yaml, falls back to defaults.
    """
    config = _load_config()
    llm_config = config.get("llm", {})

    # Get agent-specific config or fall back to defaults
    agent_config = llm_config.get("agents", {}).get(agent_name, {})
    provider_name = agent_config.get(
        "provider", llm_config.get("default_provider", "anthropic")
    )
    model_name = agent_config.get(
        "model", llm_config.get("default_model", "claude-sonnet-4-5-20250929")
    )

    # Get provider connection details
    provider_config = llm_config.get("providers", {}).get(provider_name, {})
    resolved_config = {k: _resolve_env_var(v) for k, v in provider_config.items()}

    factory = _PROVIDER_FACTORIES.get(provider_name)
    if not factory:
        raise ValueError(
            f"Unknown LLM provider: {provider_name}. "
            f"Supported: {list(_PROVIDER_FACTORIES.keys())}"
        )

    logger.info(f"Creating LLM for {agent_name}: {provider_name}/{model_name}")
    return factory(model=model_name, **resolved_config)


def get_scanning_config() -> dict:
    """Get scanning-related configuration."""
    config = _load_config()
    return config.get("scanning", {})
