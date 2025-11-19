import os
from dotenv import load_dotenv
load_dotenv()
import argparse
import requests
from datetime import datetime, timezone
import httpx

from playwright.async_api import async_playwright, TimeoutError
import asyncio

import logging
os.makedirs("logs", exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"logs/run_{timestamp}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filename=log_file,
)


MAX_CONCURRENT = 16
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

# --CONFIGS--
THREAT_TYPES = ["SOCIAL_ENGINEERING"] # can also use "MALWARE", "UNWANTED_SOFTWARE"
PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]

API_ADDR = f'{os.getenv('GOOGLE_SAFE_BROWSING_API')}?key={os.getenv('GOOGLE_SAFE_BROWSING_KEY')}'
LOCAL_SVR_ADDR = f'{os.getenv('LOCAL_ADDRESS')}'
# -----------

async def lookup(url, server_addr):
    logging.info(f'[LOOKUP] Looking up {url} in {server_addr}')

    payload = {
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}]
        }
    }
    # response = requests.post(server_addr, json=payload)
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(server_addr, json=payload)
        if response.status_code != 200:
            logging.error(f"Lookup failed with {response.status_code}: {response.text}")
            return None
        
        data = response.json()
        return data
  
async def submit(browser, url, submit_wait=1, timeout=3000):
    context = await browser.new_context()
    page = await context.new_page()
    await page.goto(os.getenv('GOOGLE_REPORT_URL'), timeout=10000)  
    await page.click("#mat-select-0")
    await page.wait_for_selector("mat-option")
    options = await page.query_selector_all("mat-option")
    for option in options:
        text = (await option.text_content() or "").strip()
        if text == "This page is not safe":
            await option.click()
            break
    url_input = "#mat-input-0"
    await page.wait_for_selector(url_input, state="visible")
    await page.fill(url_input, url)
    await page.click(".form-submit-button")
    await asyncio.sleep(submit_wait)
    # try: 
    #     await page.wait_for_selector("text=Submission was successful.", timeout=timeout)
    # except TimeoutError:
    #     await context.close()
    #     return False
    
    await context.close()
    return True

    
async def poll_local(url, server_addr, interval_min, timeout_min):
    start_time = datetime.now()
    interval_sec, timeout_sec = interval_min * 60, timeout_min * 60
 
    while (datetime.now() - start_time).total_seconds() < timeout_sec:
        data = await lookup(url, server_addr)
        if data:  # URL now exists in blacklist
            logging.info(f"[POLL COMPLETE] URL {url} now exists in blacklist: {data}")
            return True
        await asyncio.sleep(interval_sec)  # wait before next poll
    
    logging.info(f"[POLL INCOMPLETE] Timeout reached. URL {url} not in blacklist.")
    return False

def get_urls(single_url, url_file):
    url_list = []
    if single_url:
        url_list.append(single_url.strip())
    if url_file:
        with open(url_file, "r") as f:
            url_list.extend([line.strip() for line in f if line.strip()])
    return url_list

async def main():
    # LOOKUP URL
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--file")
    parser.add_argument("--poll_interval",type=float,default=60,help="Polling interval in minutes (default: 60)")
    parser.add_argument("--poll_timeout",type=float,default=14*24*60,help="Polling timeout in minutes (default: 14 days)")

    args = parser.parse_args()

    url_list = get_urls(args.url, args.file)
    if not url_list:
        parser.error("No URLs provided. Use --url or --file.")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        poll_tasks = []

        for url in url_list:
            # look up API for first check
            lookup_data = await lookup(url, API_ADDR)
    
            if lookup_data: # URL exists, so output url status and exit
                logging.debug(f'[LOOKUP RESULT] {lookup_data['matches'][0]['threatType']}')
                log = {"url": url, "time": datetime.now(),"url_exists": True}
                logging.debug(f'[STATUS] {log}')
                logging.info(f'[LOOKUP HIT] {url} already exists')
                continue

            # URL does not exist, submit URL
            logging.info(f'[LOOKUP MISS]: No match for {url}')
            submission_status = await submit(browser, url)

            if not submission_status:
                logging.error("[SUBMIT ERROR] Submission confirmation timed out.")
            else:
                logging.info(f"[SUBMIT SUCCESS] Submission for {url} was successful.")

            # Poll for changes, run concurrently in background
            task = asyncio.create_task(poll_local(url, LOCAL_SVR_ADDR, interval_min=args.poll_interval, timeout_min=args.poll_timeout))
            poll_tasks.append(task)
    
    # Wait for all polling tasks to finish (optional)
    if poll_tasks:
        await asyncio.gather(*poll_tasks)


if __name__ == "__main__":
    asyncio.run(main())