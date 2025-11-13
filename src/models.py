from pydantic import BaseModel, HttpUrl


class URLRequest(BaseModel):
    url: HttpUrl = None


class DomainTestResponse(BaseModel):
    original_url: HttpUrl = None
    domain_status: bool = False
    scannig_results: list = []

class DynamicTestResponse(BaseModel):
    oginal_uwwrl: HttpUrl = None
    phishing: bool  = True
    score: int = 0
    details: dict = {}