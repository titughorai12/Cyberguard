from pprint import pprint

from app.services.url_service import analyze_url


test_url = "http://secure-account-login.xyz/verify"

print("=" * 60)
print("CYBERGUARD COMBINED URL ANALYSIS")
print("=" * 60)

result = analyze_url(test_url)

pprint(result)

print("=" * 60)

if result.get("success"):
    print("URL SERVICE TEST COMPLETED")
else:
    print("URL SERVICE REPORTED AN ERROR")