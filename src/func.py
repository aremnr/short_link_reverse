import re
import requests
import os
import hashlib
import time

class PhishingDetector:
    def __init__(self):
        self.url_extract_regexp = r"(?P<lookbehind>(?<=url=)|(?<=href=))([\"']?)(?P<url>.+?)\2(?P<lookhead>(?=[;\\(){} <>]))"
        self.domain_extract_regexp = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:.\.)?([^:\/\n]+)"


    def extract_domain(self, url):
        is_active_domain = True
        try:
            res = requests.request("GET", url, allow_redirects=False)
        except Exception as e:
            is_active_domain = False

        if not is_active_domain:
            domain_match = re.search(self.domain_extract_regexp, url, re.IGNORECASE)
            if domain_match:
                return {"domain": domain_match.group(1), "full_url": url, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}

        if 'Location' in res.headers:
            location = res.headers['Location']
            domain_match = re.search(self.domain_extract_regexp, location, re.IGNORECASE)
            if domain_match:
                return {"domain": domain_match.group(1), "full_url": location, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}
                # return {"error": "No domain found in Location header"}   
        
        content = res.content.decode()
        match = re.search(self.url_extract_regexp, content, re.IGNORECASE)
        if match:
            extracted_url = match.group("url").strip('\'"')
            domain_match = re.search(self.domain_extract_regexp, extracted_url, re.IGNORECASE)
            if domain_match:
                return {"domain": domain_match.group(1), "full_url": extracted_url, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}

        return {"error": "No redirect URL found", "is_active": is_active_domain}
    

    def check_google_safebrowsing(self, url):
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
            response = requests.post(
                f"{api_url}?key={api_key}",
                headers=headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            result = response.json()
            if result.get("matches"):
                return {"phishing": True, "details": result["matches"]}
            else:
                return {"phishing": False, "details": response.json()}
        except Exception as e:
            return {"error": str(e)}


    def check_open_source(self, url):
        try:
            headers = {
            "User-Agent": "phishtank/username"
            }
            phishtank_api = "https://checkurl.phishtank.com/checkurl/"
            data = {
                "url": url,
                "format": "json"
            }
            response = requests.post(phishtank_api, data=data, timeout=10, headers=headers)
            response.raise_for_status()
            result = response.json()
            if result["meta"]["status"] == "success":
                return {"phishing": True if result["results"]["in_database"] == True and result["results"]["verified"] != True else False, "details": result["results"]}
            else:
                return {"phishing": False, "details": {"info": "Not found in PhishTank database", "url": url}}
        except Exception as e:
            return {"error": str(e)}


    def local_phishing_check(self, url, dir="phishing_db"):
        if not(os.path.exists(dir)):
            os.mkdir(dir)

        if "phishing-domains-ACTIVE.txt" in os.listdir(dir) and "phishing-links-ACTIVE.txt" in os.listdir(dir):
            with open(os.path.join(dir, "phishing-links-ACTIVE.txt"), "r", encoding="utf-8") as f, open(os.path.join(dir, "phishing-domains-ACTIVE.txt"), "r", encoding="utf-8") as f2:
                links = f.read().splitlines()
                domains = f2.read().splitlines()
                domain = self.extract_domain(url).get("domain", "")
                if url in links or domain in domains:
                    return {"phishing": True, "details": "Found in local database"}
                else:
                    return {"phishing": False, "details": "Not found in local database"}
        else:
            file_of_links = requests.get("https://phish.co.za/latest/phishing-links-ACTIVE.txt")
            file_of_domains = requests.get("https://phish.co.za/latest/phishing-domains-ACTIVE.txt")
            hash_of_links_file = requests.get("https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-links-ACTIVE.txt.sha256").content.decode().strip().split()[0]
            hash_of_domains_file = requests.get("https://raw.githubusercontent.com/Phishing-Database/checksums/refs/heads/master/phishing-domains-ACTIVE.txt.sha256").content.decode().strip().split()[0]
            if hashlib.sha256(file_of_links.content).hexdigest() != hash_of_links_file or hashlib.sha256(file_of_domains.content).hexdigest() != hash_of_domains_file:
                return {"error": "Hash mismatch in downloaded files"}
            with open(os.path.join(dir, "phishing-links-ACTIVE.txt"), "wb") as f, open(os.path.join(dir, "phishing-domains-ACTIVE.txt"), "wb") as f2:
                f.write(file_of_links.content)
                f2.write(file_of_domains.content)

        return {"phishing": False, "details": "Local check not implemented"}


    def get_data_from_all_sources(self, url):
        extracted_urls_dict = self.extract_domain(url)
        urls = [url, extracted_urls_dict.get("full_url", ""), extracted_urls_dict.get("domain", ""), f"http://{extracted_urls_dict.get('domain', '')}/", f"https://{extracted_urls_dict.get('domain', '')}/"]
        google_check_urls_results = []
        open_source_check_urls_results = []
        local_check_urls_results = []
        print(urls, extracted_urls_dict)
        print(extracted_urls_dict.get("is_active", False), extracted_urls_dict["is_active"])
        for url in urls:
            t1 = time.time()
            google_check_urls_results.append(self.check_google_safebrowsing(url))
            t2 = time.time()
            print(url, "Google check time:", t2 - t1)
            open_source_check_urls_results.append(self.check_open_source(url))
            t1 = time.time()
            print(url, "Open source check time:", t1 - t2)
            local_check_urls_results.append(self.local_phishing_check(url))
            t2 = time.time()
            print(url, "Local check time:", t2 - t1)
        
        return {
            "original_url": extracted_urls_dict.get("full_url", ""),
            "domain_status": extracted_urls_dict.get("is_active", False),
            "google_safebrowsing": google_check_urls_results,
            "open_source": open_source_check_urls_results,
            "local_check": local_check_urls_results
        }