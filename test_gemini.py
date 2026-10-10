from app.services.gemini_service import analyze_threat


# Test URL for cybersecurity analysis.
test_url = "http://example-login-security.test"

print("Testing CyberGuard Gemini AI...")
print("-" * 40)

result = analyze_threat(test_url)

for key, value in result.items():
    print(f"{key}: {value}")

print("-" * 40)

if result.get("success"):
    print("SUCCESS: Gemini AI is responding!")
else:
    print("FAILED: Gemini AI could not complete the test.")
    print("Check your API key, model name, and server output.")