@echo off
rem Serves the settings page on this PC only (127.0.0.1) and opens it in Edge.
rem Web Serial needs a secure page, and localhost counts as one.
start "" msedge "http://127.0.0.1:8765/"
"%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -m http.server 8765 --bind 127.0.0.1 --directory "%~dp0."
