import os
import json
import logging
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
from google import genai
# pyrefly: ignore [missing-import]
from google.genai import types

logger = logging.getLogger("ForensicLens.AI")

class GeminiClient:
    def __init__(self):
        self.default_model = "gemini-3.6-flash"
        self.fallback_model = "gemini-flash-latest"
        self._client = None
        self._api_key = None

    def _ensure_client(self):
        # Reload environment from .env so modifications take effect immediately without server restart
        load_dotenv(override=True)
        key = os.getenv("GEMINI_API_KEY", "").strip()
        if not key or key == "your_api_key_here":
            self._client = None
            self._api_key = None
            return None

        if self._client is None or self._api_key != key:
            try:
                self._client = genai.Client(api_key=key)
                self._api_key = key
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
                self._client = None
                self._api_key = None
        return self._client

    @property
    def client(self):
        return self._ensure_client()

    def is_available(self) -> bool:
        return self._ensure_client() is not None

    def analyze(self, system_instruction: str, content: str, schema: dict) -> dict:
        """
        Sends context to Gemini and enforces a JSON schema response.
        """
        return self.analyze_chat(system_instruction, [content], schema)

    def analyze_chat(self, system_instruction: str, contents: list, schema: dict = None) -> dict:
        """
        Sends multi-turn or single-turn contents to Gemini and returns parsed JSON.
        """
        client = self._ensure_client()
        if not client:
            return {"error": "AI Analyst temporarily unavailable. Missing or invalid API key in .env file."}

        config_args = {
            "system_instruction": system_instruction,
            "temperature": 0.2,
            "response_mime_type": "application/json",
        }
        if schema:
            config_args["response_schema"] = schema

        config = types.GenerateContentConfig(**config_args)

        # Attempt with primary model, then fallback if needed
        models_to_try = [self.default_model, self.fallback_model]
        last_error = None

        for model_name in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    config=config,
                )

                if response.text:
                    try:
                        return json.loads(response.text)
                    except json.JSONDecodeError:
                        # Sometimes json wrapped in markdown ticks
                        raw = response.text.strip()
                        if raw.startswith("```json"):
                            raw = raw[7:]
                        if raw.startswith("```"):
                            raw = raw[3:]
                        if raw.endswith("```"):
                            raw = raw[:-3]
                        return json.loads(raw.strip())
                else:
                    return {"error": "Model returned empty response."}

            except Exception as e:
                last_error = e
                logger.warning(f"Model {model_name} failed: {e}. Trying fallback if available.")

        logger.error(f"All Gemini models failed: {last_error}")
        return {"error": f"AI Analyst temporarily unavailable. ({str(last_error)})"}

