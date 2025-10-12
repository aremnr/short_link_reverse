import re
import aiohttp
import asyncio
import os
import hashlib
import time

class PhishingDetector:
    def __init__(self):
        self.url_extract_regexp = r"(?P<lookbehind>(?<=url=)|(?<=href=))?([\"\'])?(?P<url>https?://[^&;]+?)(?P<lookhead>((?=\2)|[&;\s<]|$))"
        self.domain_extract_regexp = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:.\.)?([^:\/\n]+)"


    async def extract_domain(self, url):
        is_active_domain = True
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, allow_redirects=False) as res:
                    headers = res.headers
                    content = await res.text("utf-8")
        except Exception as e:
            is_active_domain = False
            headers = {}
            content = ""

        if not is_active_domain:
            domain_match = re.match(self.domain_extract_regexp, url, re.IGNORECASE)
            if domain_match:
                return {"domain": domain_match.group(1), "full_url": url, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}
        
        if 'Location' in headers:
            location = headers['Location']
            domain_match = re.search(self.domain_extract_regexp, location, re.IGNORECASE)
            if domain_match:
                return {"domain": domain_match.group(1), "full_url": location, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}

        match = re.search(self.url_extract_regexp, content, re.IGNORECASE)
        if match:
            extracted_url = match.group("url").strip('\'\"')
            domain_match = re.search(self.domain_extract_regexp, extracted_url, re.IGNORECASE)
            if domain_match:
                return {"domain": domain_match.group(1), "full_url": extracted_url, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}

        return {"error": "No redirect URL found", "is_active": is_active_domain}
    

    async def check_google_safebrowsing(self, url):
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        api_key = "AIzaSyCFMCTavxG2fV2lRWBzHd58IVDF8jZJKgY"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        payload = {
            "client": {
                "clientId": "yourcompanyname",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{api_url}?key={api_key}", headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    result = await response.json()
                    if result.get("matches"):
                        return {"phishing": True, "details": result["matches"]}
                    else:
                        return {"phishing": False, "details": result}
        except Exception as e:
            return {"error": str(e)}


    async def check_open_source(self, url):
        try:
            headers = {
                "User-Agent": "phishtank/username"
            }
            phishtank_api = "https://checkurl.phishtank.com/checkurl/"
            data = {
                "url": url,
                "format": "json"
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(phishtank_api, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    result = await response.json()
                    if result["meta"]["status"] == "success":
                        return {"phishing": True if result["results"]["in_database"] == True and result["results"]["verified"] != True else False, "details": result["results"]}
                    else:
                        return {"phishing": False, "details": {"info": "Not found in PhishTank database", "url": url}}
        except Exception as e:
            return {"error": str(e)}


    async def local_phishing_check(self, url, dir="phishing_db"):
        if not(os.path.exists(dir)):
            os.mkdir(dir)

        if "phishing-domains-ACTIVE.txt" in os.listdir(dir) and "phishing-links-ACTIVE.txt" in os.listdir(dir):
            with open(os.path.join(dir, "phishing-links-ACTIVE.txt"), "r", encoding="utf-8") as f, open(os.path.join(dir, "phishing-domains-ACTIVE.txt"), "r", encoding="utf-8") as f2:
                links = f.read().splitlines()
                domains = f2.read().splitlines()
                domain = (await self.extract_domain(url)).get("domain", "")
                if url in links or domain in domains:
                    return {"phishing": True, "details": "Found in local database"}
                else:
                    return {"phishing": False, "details": "Not found in local database"}
        else:
            async with aiohttp.ClientSession() as session:
                file_of_links_resp = await session.get("https://phish.co.za/latest/phishing-links-ACTIVE.txt")
                file_of_domains_resp = await session.get("https://phish.co.za/latest/phishing-domains-ACTIVE.txt")
                hash_of_links_file_resp = await session.get("https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha256")
                hash_of_domains_file_resp = await session.get("https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha256")
                file_of_links = await file_of_links_resp.read()
                file_of_domains = await file_of_domains_resp.read()
                hash_of_links_file = (await hash_of_links_file_resp.text()).strip().split()[0]
                hash_of_domains_file = (await hash_of_domains_file_resp.text()).strip().split()[0]
                if hashlib.sha256(file_of_links).hexdigest() != hash_of_links_file or hashlib.sha256(file_of_domains).hexdigest() != hash_of_domains_file:
                    return {"error": "Hash mismatch in downloaded files"}
                with open(os.path.join(dir, "phishing-links-ACTIVE.txt"), "wb") as f, open(os.path.join(dir, "phishing-domains-ACTIVE.txt"), "wb") as f2:
                    f.write(file_of_links)
                    f2.write(file_of_domains)

        return {"phishing": False, "details": "Local check not implemented"}


    async def get_data_from_all_sources(self, url):
        extracted_urls_dict = await self.extract_domain(url)
        urls = [url, extracted_urls_dict.get("full_url", ""), extracted_urls_dict.get("domain", ""), f"http://{extracted_urls_dict.get('domain', '')}/", f"https://{extracted_urls_dict.get('domain', '')}/"]
        google_check_urls_results = []
        open_source_check_urls_results = []
        local_check_urls_results = []
        print(urls, extracted_urls_dict)
        print(extracted_urls_dict.get("is_active", False), extracted_urls_dict["is_active"])
        for url_item in urls:
            t1 = time.time()
            google_check_urls_results.append(await self.check_google_safebrowsing(url_item))
            t2 = time.time()
            print(url_item, "Google check time:", t2 - t1)
            open_source_check_urls_results.append(await self.check_open_source(url_item))
            t1 = time.time()
            print(url_item, "Open source check time:", t1 - t2)
            local_check_urls_results.append(await self.local_phishing_check(url_item))
            t2 = time.time()
            print(url_item, "Local check time:", t2 - t1)
        return {
            "original_url": extracted_urls_dict.get("full_url", ""),
            "domain_status": extracted_urls_dict.get("is_active", False),
            "google_safebrowsing": google_check_urls_results,
            "open_source": open_source_check_urls_results,
            "local_check": local_check_urls_results
    }