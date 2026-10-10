from pprint import pprint

from app.ml.url_classifier import classify_url


test_urls = [
    "https://www.google.com",
    "http://192.168.1.1/login",
    "http://secure-account-login.xyz/verify",
    "https://example.com",
]

print("=" * 60)
print("CYBERGUARD URL CLASSIFIER TEST")
print("=" * 60)

for url in test_urls:
    print(f"\nTesting URL: {url}")
    print("-" * 60)

    result = classify_url(url)

    pprint(result)

print("\n" + "=" * 60)
print("URL CLASSIFIER TEST COMPLETED")
print("=" * 60)