from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from functions import FileHandler
import os
from pathlib import Path


app = FastAPI()

templates = Jinja2Templates(directory="templates")
file_handler = FileHandler()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    input_files = file_handler.get_input_files()
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "input_files": input_files}
    )

@app.post("/process")
async def process_file(request: Request, inputFile: str = Form(...)):
    try:
        input_files = file_handler.get_input_files()
        result = file_handler.process_file(inputFile)
        
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "input_files": input_files,
                "selected_file": inputFile,
                "file_content": result['content'],
                "file_stats": result['stats'],
                "analysis_summary": result.get('analysis_summary', {}),
                "extracted_functions": result.get('extracted_functions', []),
                "decompiler": result.get('decompiler', 'unknown'),
                "architecture": result.get('architecture', 'unknown'),
                "obfuscation_detected": result.get('obfuscation_detected', False),
                "anti_debug_detected": result.get('anti_debug_detected', False)
            }
        )
    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "input_files": file_handler.get_input_files(),
                "error": str(e)
            }
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
