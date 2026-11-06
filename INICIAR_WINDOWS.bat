@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0"
echo ========================================
echo    SISTEMA DE COMPANIA DE BUSES
echo ========================================
where py > nul 2> nul
if %errorlevel% neq 0 (
  echo Instale Python 3.11 o superior desde python.org
  pause
  exit /b 1
)
if not exist .venv\Scripts\python.exe (
  echo Creando entorno virtual...
  py -3 -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo No se pudieron instalar las dependencias. Compruebe su Internet.
  pause
  exit /b 1
)
echo.
echo Inicializando base y comprobando administrador...
python manage.py init
echo.
echo.
set /p CARGAR="¿Desea cargar datos FICTICIOS para ver el sistema? (S/N): "
if /I "%CARGAR%"=="S" python manage.py demo
echo.
echo Abra en su navegador: http://127.0.0.1:8000
echo Para cerrar el servidor, presione Ctrl+C.
python run.py
pause
