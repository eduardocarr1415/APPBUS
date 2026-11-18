@echo off
REM Genera dist\BusGestion\ con BusGestion.exe listo para copiar a otro PC.
REM Solo se necesita en el PC de desarrollo (requiere Python y el entorno .venv).
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo No existe .venv. Cree el entorno: py -3 -m venv .venv
  pause & exit /b 1
)
.venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller || (pause & exit /b 1)
.venv\Scripts\python.exe -m PyInstaller BusGestion.spec --noconfirm --distpath dist\BusGestion --workpath build || (pause & exit /b 1)
copy /Y LEEME_EXE.txt dist\BusGestion\LEEME.txt > nul
echo.
echo Listo: copie la carpeta dist\BusGestion completa al PC de destino.
pause
