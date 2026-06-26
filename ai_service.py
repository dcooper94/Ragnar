#!/usr/bin/env python3
"""
AI Service for Ragnar
GPT-5 version using OpenAI SDK 2.x
Provides intelligent network analysis, summaries, and insights.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from openai import OpenAI

from logger import Logger
from env_manager import EnvManager, load_env

# Load environment variables immediately
load_env()


# ===================================================================
#   AI SERVICE
# ===================================================================

class AIService:
    """AI-powered network analysis, vulnerability interpretation, and insights."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = Logger(name="AIService", level=logging.INFO)
        self.env_manager = EnvManager()

        cfg = shared_data.config

        # Configuration
        self.enabled = cfg.get("ai_enabled", False)
        self.model = cfg.get("ai_model", "gpt-5.1")

        # These must remain for backward compatibility (but not used)
        self.max_tokens = cfg.get("ai_max_tokens")
        self.temperature = cfg.get("ai_temperature")
        self.temperature_supported = True  # will disable on first failure

        self.vulnerability_summaries = cfg.get("ai_vulnerability_summaries", True)
        self.network_insights = cfg.get("ai_network_insights", True)

        self.api_token = self.env_manager.get_token()

        # Local / custom provider support
        # ai_provider: "openai" (default) | "ollama" | "lmstudio" | "custom"
        # ai_base_url: override endpoint URL (e.g. "http://localhost:11434/v1")
        # ai_local_model: model name to use with local providers (e.g. "llama3.2")
        self.provider = cfg.get("ai_provider", "openai").lower()
        self.base_url = cfg.get("ai_base_url", None)
        self.local_model = cfg.get("ai_local_model", None)

        # Cache
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour (3600 seconds) - reduce token consumption

        # Client initialization
        self.client = None
        self.initialization_error = None
        self._initialize_client()



    # ===================================================================
    #   INITIALIZATION
    # ===================================================================

    _PROVIDER_DEFAULTS = {
        "ollama":   "http://localhost:11434/v1",
        "lmstudio": "http://localhost:1234/v1",
        "custom":   "http://localhost:11434/v1",
    }

    def _initialize_client(self):
        if not self.enabled:
            return

        is_local = self.provider != "openai"

        if not is_local and not self.api_token:
            self.initialization_error = "No OpenAI API key found."
            self.logger.warning(self.initialization_error)
            return

        try:
            if is_local:
                base_url = self.base_url or self._PROVIDER_DEFAULTS.get(
                    self.provider, "http://localhost:11434/v1"
                )
                # Local providers accept any non-empty string as the API key
                api_key = self.api_token or "local"
                self.client = OpenAI(base_url=base_url, api_key=api_key)
                effective_model = self.local_model or self.model
                self.logger.info(
                    f"AI Service initialized — provider: {self.provider} "
                    f"url: {base_url} model: {effective_model}"
                )
            else:
                self.client = OpenAI(api_key=self.api_token)
                self.logger.info(f"AI Service initialized using model: {self.model}")

            self.initialization_error = None
        except Exception as exc:
            self.client = None
            self.initialization_error = f"AI client initialization failed: {exc}"
            self.logger.error(self.initialization_error)


    def reload_token(self) -> bool:
        """Refresh the API token from disk and reinitialize the AI client."""

        # Keep config in sync
        if hasattr(self.shared_data, "config"):
            cfg = self.shared_data.config
            self.enabled = cfg.get("ai_enabled", self.enabled)
            self.provider = cfg.get("ai_provider", self.provider).lower()
            self.base_url = cfg.get("ai_base_url", self.base_url)
            self.local_model = cfg.get("ai_local_model", self.local_model)

        self.api_token = self.env_manager.get_token()
        self.client = None
        self.initialization_error = None

        if not self.enabled:
            self.logger.info("AI service disabled in config; skipping token reload.")
            return False

        is_local = self.provider != "openai"
        if not self.api_token and not is_local:
            self.logger.warning("AI token reload requested but no token present in environment.")
            self.initialization_error = "No OpenAI API key found."
            return False

        self._initialize_client()
        success = self.client is not None and self.initialization_error is None

        if success:
            self.logger.info("AI service reloaded with updated token.")
        else:
            if self.initialization_error:
                self.logger.error(
                    f"AI service failed to reinitialize after token reload: {self.initialization_error}"
                )
            else:
                self.logger.error("AI service failed to reinitialize after token reload.")

        return success



    # ===================================================================
    #   UTILITY HELPERS
    # ===================================================================

    def is_enabled(self):
        """Return True when the service is enabled and the client is ready."""
        return self.ensure_ready()

    def ensure_ready(self):
        """Lazily initialize the OpenAI client if configuration says AI is enabled."""
        # Sync enabled state with config in case it changed
        if hasattr(self.shared_data, "config"):
            self.enabled = self.shared_data.config.get("ai_enabled", self.enabled)
        
        if not self.enabled:
            return False

        # Already initialized and healthy
        if self.client is not None and self.initialization_error is None:
            return True

        # Don't keep retrying when we've already recorded a permanent failure
        # But allow retry if token was added after initial failure
        if self.initialization_error and self.api_token:
            # Clear error and retry if we have a token now
            self.initialization_error = None

        # Refresh token from disk if we don't have one yet
        if not self.api_token:
            self.api_token = self.env_manager.get_token()

        is_local = self.provider != "openai"
        if not self.api_token and not is_local:
            self.initialization_error = "No OpenAI API key found."
            self.logger.warning(self.initialization_error)
            return False

        self._initialize_client()
        return self.client is not None and self.initialization_error is None

    def _cache_key(self, name: str, content: Any):
        import hashlib
        raw = f"{name}:{json.dumps(content, sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _cache_get(self, key: str):
        item = self.cache.get(key)
        if not item:
            return None
        if time.time() - item["timestamp"] > self.cache_ttl:
            del self.cache[key]
            return None
        return item["value"]

    def _cache_set(self, key: str, value: Any):
        self.cache[key] = {"timestamp": time.time(), "value": value}



    # ===================================================================
    #   CORE GPT-5 CALL — NEW RESPONSES API
    # ===================================================================

    def _ask(self, system_msg: str, user_msg: str) -> Optional[str]:
        """Route to the correct API based on provider."""
        if not self.is_enabled():
            return None
        if self.client is None:
            self.logger.error("AI client unavailable despite service being enabled.")
            return None

        if self.provider == "openai":
            return self._ask_responses_api(system_msg, user_msg)
        else:
            return self._ask_chat_completions(system_msg, user_msg)

    def _ask_responses_api(self, system_msg: str, user_msg: str) -> Optional[str]:
        """Call the OpenAI Responses API (GPT-5 / cloud only)."""
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            "reasoning": {"effort": "low"},
            "text": {"verbosity": "low"},
        }

        if self.temperature_supported and self.temperature is not None:
            payload["temperature"] = self.temperature

        try:
            result = self.client.responses.create(**payload)
            return self._extract_responses_output(result)
        except Exception as e:
            error_text = str(e).lower()
            if "temperature" in error_text and "unsupported" in error_text:
                self.temperature_supported = False
                self.logger.warning("Model reported temperature unsupported — retrying without it.")
                payload.pop("temperature", None)
                try:
                    result = self.client.responses.create(**payload)
                    return self._extract_responses_output(result)
                except Exception as e2:
                    self.logger.error(f"Retry without temperature failed: {e2}")
                    return None
            self.logger.error(f"OpenAI Responses API call failed: {e}")
            return None

    def _ask_chat_completions(self, system_msg: str, user_msg: str) -> Optional[str]:
        """Call the Chat Completions API — compatible with Ollama, LM Studio, and any OpenAI-compatible endpoint."""
        model = self.local_model or self.model
        try:
            result = self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                timeout=120,
            )
            if result.usage:
                u = result.usage
                self.logger.info(
                    f"AI Tokens → input:{u.prompt_tokens} output:{u.completion_tokens} "
                    f"total:{u.total_tokens}"
                )
            return result.choices[0].message.content.strip()
        except Exception as e:
            self.logger.error(f"Chat completions call failed ({self.provider}): {e}")
            return None

    def _extract_responses_output(self, result):
        """Extract output text from OpenAI Responses API result."""
        if hasattr(result, "usage"):
            u = result.usage
            self.logger.info(
                f"AI Tokens → input:{u.input_tokens} output:{u.output_tokens} total:{u.total_tokens}"
            )
        try:
            return result.output_text.strip()
        except Exception:
            return None
    # ===================================================================
    #   NETWORK SUMMARY
    # ===================================================================

    def analyze_network_summary(self, network_data):
        if not self.is_enabled() or not self.network_insights:
            return None

        key = self._cache_key("summary", network_data)
        cached = self._cache_get(key)
        if cached:
            return cached

        system = (
            "You are Ragnar, a witty cybersecurity Viking AI. "
            "Provide concise, aggressive but clear summaries."
        )

        user = f"""
Analyze this network scan:

Targets: {network_data.get('target_count')}
Open Ports: {network_data.get('port_count')}
Vulnerabilities Found: {network_data.get('vulnerability_count')}
Credentials Found: {network_data.get('credential_count')}

Give a 2–3 sentence Viking-style summary.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   VULNERABILITY ANALYSIS
    # ===================================================================

    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]):
        if not self.is_enabled() or not self.vulnerability_summaries:
            return None

        key = self._cache_key("vuln_analysis", {"count": len(vulnerabilities)})
        cached = self._cache_get(key)
        if cached:
            return cached

        limited = vulnerabilities[:10]
        data_json = json.dumps(limited, indent=2)

        system = (
            "You are Ragnar, an elite vulnerability hunter. "
            "Structure your analysis clearly with sections and bullet points. "
            "Use markdown-style formatting for readability."
        )

        user = f"""
Vulnerabilities Detected: {len(vulnerabilities)}

Top Findings:
{data_json}

Provide a structured analysis:

First, give a brief Viking-style tactical summary (max 50 words) of the overall vulnerability situation.

Then provide detailed analysis:

**Critical Weaknesses:**
- List the most severe vulnerabilities (CVE numbers if available)
- Include affected hosts/ports
- Note severity ratings

**Immediate Actions Required:**
- Prioritized remediation steps
- What to patch/fix first
- Quick wins for risk reduction

**Overall Risk Assessment:**
- Current attack surface severity (Critical/High/Medium)
- Potential impact if exploited
- Recommended timeline for fixes

Tone: Direct, tactical Viking strategist. Use bullet points and clear sections.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   ATTACK VECTOR IDENTIFICATION
    # ===================================================================

    def identify_network_weaknesses(self, network_data: Dict, findings: List[Dict]):
        if not self.is_enabled():
            return None

        key = self._cache_key("weakness", {
            "targets": network_data.get("target_count"),
            "findings": len(findings),
        })
        cached = self._cache_get(key)
        if cached:
            return cached

        sample = json.dumps(findings[:5], indent=2)

        system = (
            "You are Ragnar, a penetration strategist. "
            "Structure attack vector analysis clearly with numbered attack paths. "
            "Use markdown formatting for readability."
        )

        user = f"""
Network Profile:
- Devices: {network_data.get('target_count')}
- Open Ports: {network_data.get('port_count')}

Key Findings:
{sample}

Provide structured attack vector analysis:

First, give a brief, witty Viking-style summary (max 50 words) describing the network's exploitability and main attack surface.

Then provide detailed attack paths:

**Primary Attack Paths:**

1. **[Attack Name]**
   - Target: [specific host/service]
   - Method: [exploitation technique]
   - Risk Level: [Critical/High/Medium]
   - Ease of Exploitation: [Easy/Moderate/Difficult]

2. **[Attack Name]**
   - Target: [specific host/service]
   - Method: [exploitation technique]
   - Risk Level: [Critical/High/Medium]
   - Ease of Exploitation: [Easy/Moderate/Difficult]

3. **[Attack Name]** (if applicable)
   - Target: [specific host/service]
   - Method: [exploitation technique]
   - Risk Level: [Critical/High/Medium]
   - Ease of Exploitation: [Easy/Moderate/Difficult]

**Defense Recommendations:**
- Immediate hardening steps
- Network segmentation suggestions

Limit to 2-3 most viable attack paths. Be specific and tactical.
"""

        resp = self._ask(system, user)
        if resp:
            self._cache_set(key, resp)
        return resp



    # ===================================================================
    #   PARALLEL BATCH PREP (FUTURE SUPPORT)
    # ===================================================================

    def analyze_batch(self, tasks: List[Dict]) -> List[Optional[str]]:
        results = []
        for t in tasks:
            results.append(self._ask(t["system"], t["user"]))
        return results



    # ===================================================================
    #   COMBINED INSIGHTS FOR UI
    # ===================================================================

    def generate_insights(self):
        output = {
            "enabled": self.is_enabled(),
            "timestamp": datetime.now().isoformat(),
            "network_summary": None,
            "vulnerability_analysis": None,
            "weakness_analysis": None,
        }

        if not self.is_enabled():
            output["message"] = self.initialization_error or "AI disabled"
            return output

        net = {
            "target_count": self.shared_data.targetnbr,
            "port_count": self.shared_data.portnbr,
            "vulnerability_count": self.shared_data.vulnnbr,
            "credential_count": self.shared_data.crednbr,
        }

        # Summary
        output["network_summary"] = self.analyze_network_summary(net)

        # Additional analyses if intelligence system is available
        if hasattr(self.shared_data, "network_intelligence") and \
           self.shared_data.network_intelligence:

            findings = self.shared_data.network_intelligence.get_active_findings_for_dashboard()

            vulns = list(findings.get("vulnerabilities", {}).values())
            if vulns:
                output["vulnerability_analysis"] = self.analyze_vulnerabilities(vulns)

                creds = list(findings.get("credentials", {}).values())
                combined = vulns + creds
                output["weakness_analysis"] = self.identify_network_weaknesses(net, combined)

        return output



    # ===================================================================
    #   CACHE CLEAR
    # ===================================================================

    def clear_cache(self):
        self.cache.clear()
        self.logger.info("AI cache cleared")
