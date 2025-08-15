import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn
import threading

app = FastAPI()

# Streamlit'i ayrı bir thread'de başlat
@app.on_event("startup")
def start_streamlit():
    def run():
        os.system("streamlit run app.py --server.port 8501 --server.headless true")
    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    # Streamlit arayüzünü iframe ile göm
    return """
    <html>
      <head><title>Cybertrack Vision</title></head>
      <body style='margin:0;padding:0;'>
        <iframe src="http://localhost:8501" width="100%" height="100%" style="border:none;position:fixed;top:0;left:0;bottom:0;right:0;width:100vw;height:100vh;"></iframe>
      </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
