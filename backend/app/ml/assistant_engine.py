import logging
import json

from google import genai
from google.genai import types

from app.core.config import settings

logger = logging.getLogger(__name__)
FALLBACK_MODEL = "gemini-3.8-flash"


def ask_assistant(question: str) -> dict:
    """Answer a cybersecurity question using Gemini AI."""

    if not isinstance(question, str) or not question.strip():
        return {
            "success": False,
            "message": "Please provide a question.",
        }

    if not settings.GEMINI_API_KEY:
        return {
            "success": False,
            "message": "Gemini AI is not configured.",
        }

    question = question.strip()

    prompt = f"""
You are CyberGuard Assistant, a helpful cybersecurity assistant.

Answer the user's cybersecurity question clearly and simply.
When the user asks how to respond, give a short ordered set of practical steps, starting with the safest immediate action. Avoid jargon and never ask for secrets.

Rules:
- Give beginner-friendly explanations.
- Focus on cybersecurity, online safety, phishing, malware,
  passwords, privacy, URLs, scams, and related topics.
- Do not provide instructions for hacking, malware creation,
  credential theft, bypassing security, or other harmful activity.
- If the question is unsafe, explain the safe alternative.
- Keep the answer concise but useful.

User question:
{question}

Return ONLY valid JSON in this format:
{{
    "answer": "Your answer here",
    "steps": ["Action one", "Action two"],
    "recommended_action": "A useful safety recommendation"
}}
"""

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        configured_model = (settings.GEMINI_MODEL or FALLBACK_MODEL).strip()
        models_to_try = list(dict.fromkeys([configured_model, FALLBACK_MODEL]))
        response = None
        selected_model = configured_model
        for index, model in enumerate(models_to_try):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.2,
                        response_mime_type="application/json",
                    ),
                )
                selected_model = model
                break
            except Exception as model_error:
                status_code = (
                    getattr(model_error, "code", None)
                    or getattr(model_error, "status_code", None)
                )
                if index == 0 and len(models_to_try) > 1 and status_code == 404:
                    logger.warning(
                        "Configured Gemini model %s is unavailable; retrying with %s.",
                        model,
                        FALLBACK_MODEL,
                    )
                    continue
                raise

        if response is None:
            raise RuntimeError("Gemini did not return a response.")

        text = (response.text or "").strip()

        if not text:
            return {
                "success": False,
                "message": "Gemini returned an empty response.",
            }

        data = json.loads(text)

        answer = data.get("answer", "").strip()
        raw_steps = data.get("steps", [])
        if not isinstance(raw_steps, list):
            raw_steps = []
        steps = [step.strip() for step in raw_steps if isinstance(step, str) and step.strip()][:5]

        recommended_action = data.get(
            "recommended_action",
            "",
        ).strip()

        if not answer:
            return {
                "success": False,
                "message": "Gemini did not return a valid answer.",
            }

        return {
            "success": True,
            "message": "Assistant response generated.",
            "data": {
                "question": question,
                "answer": answer,
                "recommended_action": recommended_action,
                "steps": steps,
                "ai_provider": "gemini",
                "ai_model": selected_model,
            },
        }

    except Exception as error:
        logger.exception("CyberGuard Assistant failed.")
        status_code = getattr(error, "code", None) or getattr(error, "status_code", None)
        if status_code in {401, 403}:
            message = "Gemini rejected the API key or the key lacks API access. Check GEMINI_API_KEY in Render."
        elif status_code == 429:
            message = "Gemini's request quota or rate limit was reached. Check Google AI Studio usage and try again later."
        elif status_code == 404:
            message = f"The configured Gemini model is unavailable. Set GEMINI_MODEL to {FALLBACK_MODEL} in Render and redeploy."
        else:
            message = "Gemini could not complete the request. Check the Render service logs for the provider error."

        return {
            "success": False,
            "message": message,
        }
