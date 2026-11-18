@echo off
REM Inicio con Python instalado (modo desarrollo). En un PC sin Python use BusGestion.exe.
setlocal
cd /d "%~dp0"
echo ========================================
echo    SISTEMA DE COMPANIA DE BUSES
echo ========================================

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY (
  echo No se encontro Python. Instale Python 3.11+ desde python.org
  echo marcando "Add Python to PATH", o use BusGestion.exe.
  pause & exit /b 1
)

REM Un .venv copiado desde otro PC no funciona: se recrea si esta roto.
if exist .venv\Scripts\python.exe (
  .venv\Scripts\python.exe -c "import sys" >nul 2>nul || rmdir /s /q .venv
)
if not exist .venv\Scripts\python.exe (
  echo Creando entorno virtual...
  %PY% -m venv .venv || (echo No se pudo crear el entorno virtual. & pause & exit /b 1)
)

.venv\Scripts\python.exe -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo No se pudieron instalar las dependencias. Compruebe su Internet.
  pause & exit /b 1
)

echo.
echo Inicializando base y comprobando administrador...
.venv\Scripts\python.exe manage.py init
echo.
set "CARGAR=N"
set /p CARGAR="Desea cargar datos FICTICIOS para ver el sistema? (S/N): "
if /I "%CARGAR%"=="S" .venv\Scripts\python.exe manage.py demo
echo.
echo Abra en su navegador: http://127.0.0.1:8000
echo Para cerrar el servidor, presione Ctrl+C.
start "" http://127.0.0.1:8000
.venv\Scripts\python.exe run.py
pause
