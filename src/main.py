from fastapi import FastAPI, Request, HTTPException
import func
from models import URLRequest, DomainTestResponse, DynamicTestResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


app = FastAPI()
phishingTest = func.PhishingDetector()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", tags=["home"])
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/phishing_check_by_damain", response_model=DomainTestResponse, tags=["phishing_check"])
async def phishing_check_by_domain(request: URLRequest):
    result = await phishingTest.domain_check(request.url)
    return result

@app.post("/api/phishing_check_dynamic", response_model=DynamicTestResponse, tags=["phishing_check"])
async def phishing_check_dynamic(request: URLRequest):
    result = await phishingTest.local_dynamic_check(request.url)
    return result

@app.post("/api/phishing_check_local",response_model=DomainTestResponse, tags=["phishing_check"])
async def phishing_check_local(request: URLRequest):
    result = await phishingTest.local_domain_check(request.url)
    return result  