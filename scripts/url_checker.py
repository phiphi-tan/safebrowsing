import argparse
import requests

# Local Safe Browsing server
SB_SERVER = "http://127.0.0.1:8080/v4/threatMatches:find"

# Threat types to check
THREAT_TYPES = ["SOCIAL_ENGINEERING"] # can also use "MALWARE", "UNWANTED_SOFTWARE"
PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]

def check_urls(urls):
    payload = {
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url} for url in urls]
        }
    }
    response = requests.post(SB_SERVER, json=payload)
    if response.status_code != 200:
        raise RuntimeError(f"Error {response.status_code}: {response.text}")
    return response.json()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--file")
    args = parser.parse_args()

    to_check_urls = []
    if args.url:
        to_check_urls.append(args.url.strip())
    if args.file:
        with open(args.file, "r") as f:
            to_check_urls.extend([line.strip() for line in f if line.strip()])

    if not to_check_urls:
        print("No URLs provided. Use --url or --file.")
        return

    result = check_urls(to_check_urls)
    # print(f"Result is {result}")

    detected_urls = set()
    for match in result.get("matches", []):
        detected_urls.add(match["threat"]["url"])

    # Print results
    for url in to_check_urls:
        status = "Detected" if url in detected_urls else "Not detected"
        print(f"{url}: {status}")

if __name__ == "__main__":
    main()
