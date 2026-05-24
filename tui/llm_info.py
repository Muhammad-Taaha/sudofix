"""
LLM model detection for the TUI.
"""

import os
import subprocess


def detect_llm_model() -> dict:
    """
    Detect the active LLM model and return a dict with keys:
        model, provider, source

    Returns:
        dict: {"model": str, "provider": str, "source": str}
    """
    result = {
        "model": "unknown",
        "provider": "unknown",
        "source": "unknown"
    }

    # 1. Check environment variables
    model_env = os.getenv("LLM_MODEL") or os.getenv("REPO_LLM_MODEL")
    if model_env:
        result["model"] = model_env
        result["source"] = "env"
        result["provider"] = "env"
        return result

    # 2. Look for a local config file
    config_paths = [
        ".llm_config",
        "llm_config.json",
        ".repo-llm/config"
    ]
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    content = f.read().strip()
                    if content:
                        result["model"] = content
                        result["source"] = path
                        result["provider"] = "config"
                        return result
            except (OSError, IOError):
                pass

    # 3. Try to detect via command-line tools (ollama first)
    try:
        out = subprocess.check_output(
            ["ollama", "list"], text=True, stderr=subprocess.DEVNULL)
        lines = out.strip().split("\n")
        if len(lines) > 1:
            first_model = lines[1].split()[0]
            result["model"] = first_model
            result["provider"] = "ollama"
            result["source"] = "ollama list"
            return result
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # 4. Fallback: return unknown
    return result
