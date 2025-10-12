from fastapi import FastAPI, Request
import func
from models import URLRequest
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


app = FastAPI()
phishingTest = func.PhishingDetector()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/check")
async def check_url(url: URLRequest):
    return phishingTest.get_data_from_all_sources(url.url)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)