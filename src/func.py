import re
import aiohttp
import asyncio
import os
import hashlib
import time
from fastapi import HTTPException
from config import GOOGLE_API_KEY
from pydantic import HttpUrl
from models import DomainTestResponse, DynamicTestResponse
from urllib.parse import urlparse, parse_qs
from ipaddress import ip_address
from typing import Optional, Dict, Any, Tuple

class PhishingDetector:
    def __init__(self):
        self.url_extract_regexp = r"(?P<lookbehind>(?<=url=)|(?<=href=))?([\"\'])?(?P<url>https?://[^&;]+?)(?P<lookhead>((?=\2)|[&;\s<]|$))"
        self.domain_extract_regexp = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:.\.)?([^:\/\n]+)"
    
     
    async def request_to_site(
            self,
            url: HttpUrl, 
            method: str = "HEAD",
            allow_redirects: bool = False, 
            headers: dict = {}, 
            payload: dict = {}) -> dict:
        '''
        Base function for async requests.
        '''
        url=str(url)
        content = None
        if method == "HEAD":
            async with aiohttp.ClientSession() as session:
                async with session.head(url, allow_redirects=allow_redirects) as res:
                    headers = res.headers
                    content = ""
            return {"headers": headers, "content": content}
        if method == "GET":
            async with aiohttp.ClientSession() as session:
                async with session.get(url, allow_redirects=allow_redirects) as res:
                    headers = res.headers
                    content = await res.text()
            return {"headers": headers, "content": content}
        if method == "POST":
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as res:
                    response_headers = res.headers
                    content = await res.json()
                    return {"headers": response_headers, "content": content}


    async def extract_domain_and_url(self, url: HttpUrl) -> dict:
        '''
            Extract a url from html page or Location header.
            Return: extracted url | domain 
        '''
        is_active_domain = True
        headers, content = None, None
        try:
            res = await self.request_to_site(url)
            headers = res.get("headers")
            content = res.get("content")
            print(headers)
        except Exception as e:
            print(e)
            is_active_domain = False
            headers = {}
            content = ""

        if not is_active_domain:
            print(1)
            domain = url.host
            if domain:
                return {"domain": domain, "full_url": url, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}
        
        if 'Location' in headers:
            print(2)
            location = HttpUrl(headers['Location'])
            domain = location.host
            if domain:
                return {"domain": domain, "full_url": location, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}

        content = await self.request_to_site(url, "GET")
        content = content.get("content")
        match = re.search(self.url_extract_regexp, content, re.IGNORECASE)
        if match:
            print(3)
            extracted_url = match.group("url").strip('\'\"')
            domain = HttpUrl(extracted_url).host
            if domain:
                return {"domain": domain, "full_url": extracted_url, "is_active": is_active_domain}
            else:
                return {"error": "No domain found in extracted URL", "is_active": is_active_domain}

        return {"error": "No redirect URL found", "is_active": is_active_domain}
    

    async def check_google_safebrowsing(self, url):
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        api_key = GOOGLE_API_KEY
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
                    {"url": str(url)}
                ]
            }
        }

        try:
            response = await self.request_to_site(HttpUrl(f"{api_url}?key={api_key}"), method="POST",  headers=headers, payload=payload)
            response = response.get("content")
            if response.get("matches"):
                return {"phishing": True, "details": response["matches"]}
            else:
                return {"phishing": False, "details": response}
        except Exception as e:
            return {"error": str(e)}


    async def dynamic_check(self, url):
        """
        Расширенный анализ URL на признаки фишинга.
        """
        score = 0
        details: Dict[str, Any] = {}

        
        
        
        url_lower = url.lower()

        
        suspicious_words = {
            "login", "secure", "verify", "update", "account", "bank", "password",
            "signin", "checkout", "confirm", "paypal", "appleid", "webscr"
        }
        for word in suspicious_words:
            if word in url_lower:
                score += 2
                details.setdefault("suspicious_keywords", []).append(word)

        
        tld = url.split(".")[-1].split("/")[0]
        suspicious_tlds = {"xyz", "top", "tk", "ml", "ga", "gq", "cf", "buzz", "fit", "cam"}
        if tld in suspicious_tlds:
            score += 2
            details["suspicious_tld"] = tld

        
        if not url_lower.startswith("https://"):
            score += 2
            details["no_https"] = True

        
        host_part = re.findall(r"https?://([^/]+)/?", url_lower)
        if host_part:
            host = host_part[0]
            try:
                ip_address(host)
                score += 3
                details["ip_as_domain"] = True
            except ValueError:
                pass

       
            subdomain_count = host.count(".")
            if subdomain_count > 3:
                score += 1
                details["many_subdomains"] = subdomain_count

            
            if "@" in host or "-" in host or "_" in host:
                score += 1
                details["special_symbols"] = True

        
        if len(url) > 100:
            score += 1
            details["long_url"] = len(url)

        
        digit_count = sum(c.isdigit() for c in url)
        if digit_count > 5:
            score += 1
            details["many_digits"] = digit_count

        
        known_brands = ["paypal", "google", "apple", "microsoft", "amazon"]
        for brand in known_brands:
            if brand in url_lower and not re.search(rf"{brand}\.com", url_lower):
                score += 2
                details.setdefault("brand_mismatch", []).append(brand)

        
        
        
        html: Optional[str] = None
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200 and "text/html" in resp.headers.get("content-type", ""):
                        html = await resp.text(errors="ignore")
                    else:
                        details["non_html_content"] = True
        except Exception as e:
            details["fetch_error"] = str(e)

        
        
        
        if html:
            
            if re.search(r'<input[^>]+type=["\']?password', html, re.IGNORECASE):
                score += 3
                details["password_field_detected"] = True

            
            if re.search(r"(verify your account|login now|update info|confirm identity|enter password)", html, re.IGNORECASE):
                score += 2
                details["phishing_text"] = True

            
            if re.search(r"(mailto:|@|sendmail)", html, re.IGNORECASE):
                score += 1
                details["email_links_detected"] = True

            
            if re.search(r"(window\.location|document\.write|atob\(|eval\()", html, re.IGNORECASE):
                score += 2
                details["suspicious_js"] = True

            
            if re.search(r'src=["\']http://', html, re.IGNORECASE):
                score += 1
                details["mixed_content"] = True

            
            if re.search(r"display\s*:\s*none", html, re.IGNORECASE) or re.search(r"type=['\"]hidden['\"]", html, re.IGNORECASE):
                score += 1
                details["hidden_elements"] = True

            
            external_links = re.findall(r'href=["\'](http[s]?://[^"\']+)', html)
            unique_domains = set()
            for link in external_links:
                domain = re.findall(r"https?://([^/]+)/?", link)
                if domain:
                    unique_domains.add(domain[0].lower())
            if len(unique_domains) > 10:
                score += 1
                details["many_external_links"] = len(unique_domains)

            
            if re.search(r"data:image|data:text/html", html, re.IGNORECASE):
                score += 1
                details["data_uri_usage"] = True

        
        
        
        phishing = score >= 5  

        return DynamicTestResponse(
            original_url=url,
            phishing=phishing,
            score=score,
            details=details
        )

        


    async def local_phishing_check(self, url = "", domain = "", dir="phishing_db"):
        if not(os.path.exists(dir)):
            os.mkdir(dir)

        if "phishing-domains-ACTIVE.txt" in os.listdir(dir) and "phishing-links-ACTIVE.txt" in os.listdir(dir):
            with open(os.path.join(dir, "phishing-links-ACTIVE.txt"), "r", encoding="utf-8") as f, open(os.path.join(dir, "phishing-domains-ACTIVE.txt"), "r", encoding="utf-8") as f2:
                links = f.read().splitlines()
                domains = f2.read().splitlines()
                domain = (await self.extract_domain_and_url(HttpUrl(url))).get("domain", "") if domain == "" else domain
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


    async def domain_check(self, url: HttpUrl) -> DomainTestResponse:
        extracted_urls_dict = await self.extract_domain_and_url(url)
        print(extracted_urls_dict)
        if "error" in extracted_urls_dict.keys():
            return HTTPException(403, extracted_urls_dict)
        redirect_url, redirect_domain, domain_status = extracted_urls_dict.get("full_url", ""), extracted_urls_dict.get("domain", ""), extracted_urls_dict.get("is_active", "")
        urls = [url, redirect_url, redirect_domain]
        google_check_urls_results = []
        for url in urls:
            t1 = time.time()
            google_check_urls_results.append(await self.check_google_safebrowsing(url))
            t2 = time.time()
            print(url, t2-t1)
        
        return DomainTestResponse(
            original_url=str(redirect_url),
            domain_status=domain_status, 
            scannig_results=google_check_urls_results            
        )
    

    async def local_domain_check(self, url: HttpUrl) -> DomainTestResponse:
        extracted_urls_dict = await self.extract_domain_and_url(url)
        print(extracted_urls_dict)
        if "error" in extracted_urls_dict.keys():
            return DomainTestResponse()
        redirect_url, redirect_domain, domain_status = extracted_urls_dict.get("full_url", ""), extracted_urls_dict.get("domain", ""), extracted_urls_dict.get("is_active", "")
        urls = [url, redirect_url, redirect_domain]
        local_check_urls_results = []
        for v, url in enumerate(urls):
            if v == 2:
                t1 = time.time()
                local_check_urls_results.append(await self.local_phishing_check(domain=url))
                t2 = time.time()
                return DomainTestResponse(
                    original_url=str(redirect_url),
                    domain_status=domain_status, 
                    scannig_results=local_check_urls_results            
                )
            t1 = time.time()
            local_check_urls_results.append(await self.local_phishing_check(url=url))
            t2 = time.time()
            print(url, t2-t1)
        
        return DomainTestResponse(
            original_url=str(redirect_url),
            domain_status=domain_status, 
            scannig_results=local_check_urls_results            
        )

    async def local_dynamic_check(self, url: HttpUrl) -> DynamicTestResponse:
        extracted_urls_dict = await self.extract_domain_and_url(url)
        print(extracted_urls_dict)
        if "error" in extracted_urls_dict.keys():
            return HTTPException(403, extracted_urls_dict)
        redirect_url= str(extracted_urls_dict.get("full_url", ""))
        result: DynamicTestResponse = DynamicTestResponse()
        t1 = time.time()
        result = await self.dynamic_check(redirect_url)
        t2 = time.time()
        print(redirect_url, result, t2-t1)
        return result
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    