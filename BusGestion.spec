# -*- mode: python ; coding: utf-8 -*-
# Compilar con:  .venv\Scripts\python.exe -m PyInstaller BusGestion.spec --noconfirm
from PyInstaller.utils.hooks import collect_submodules

hidden = (collect_submodules('uvicorn') + collect_submodules('reportlab')
          + ['multipart', 'python_multipart', 'manage'])

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=[],
    # Plantillas y archivos estáticos van DENTRO del exe; la base de datos NO.
    datas=[('app/templates', 'app/templates'), ('app/static', 'app/static')],
    hiddenimports=hidden,
    excludes=['pytest', 'tkinter'],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='BusGestion',
    console=True,
    upx=False,
    runtime_tmpdir=None,
)
