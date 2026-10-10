from google import genai
from app.core.config import settings

print("Checking available Gemini models...")
print("-" * 45)

if not settings.GEMINI_API_KEY:
    print("ERROR: Gemini API key is not configured.")
    raise SystemExit(1)

try:
    client = genai.Client(
        api_key=settings.GEMINI_API_KEY
    )

    found = 0

    for model in client.models.list():
        actions = getattr(model, "supported_actions", []) or []

        if any("generateContent" in action for action in actions):
            print("Model:", model.name)
            found += 1

    print("-" * 45)
    print("Models supporting text generation:", found)

    if found == 0:
        print("No compatible models were listed.")

except Exception as error:
    print("Unable to retrieve models.")
    print("Error:", type(error).__name__, str(error)[:400])
