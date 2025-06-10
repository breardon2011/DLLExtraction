@echo off
REM Activate virtual environment
call venv\Scripts\activate.bat

REM Run the FastAPI app with Uvicorn
uvicorn main:app --reload

pause

