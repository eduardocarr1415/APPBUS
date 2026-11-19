"""Punto de entrada del ejecutable BusGestion.exe (PyInstaller).

Uso:
  BusGestion.exe               Inicia el servidor y abre el navegador.
  BusGestion.exe demo          Carga datos ficticios de demostración.
  BusGestion.exe backup        Crea una copia de seguridad en copias_seguridad/.
  BusGestion.exe reset-admin   Restablece la contraseña del usuario admin.

La base de datos se guarda en la carpeta 'instance' junto al .exe, no dentro de él.
"""
import os
import socket
import sys
import threading
import time
import traceback
import urllib.request
import webbrowser


NO_CONSOLE = sys.stdout is None  # exe compilado con console=False

if NO_CONSOLE:
    # Sin consola no hay stdout/stderr: se redirige todo a un log junto al exe.
    _log_dir = os.path.join(os.path.dirname(sys.executable), 'instance')
    os.makedirs(_log_dir, exist_ok=True)
    sys.stdout = sys.stderr = open(os.path.join(_log_dir, 'busgestion.log'),
                                   'a', encoding='utf-8', buffering=1)


def pause():
    if NO_CONSOLE:
        return
    try:
        input('\nPresione ENTER para cerrar...')
    except (EOFError, RuntimeError):
        pass


def port_free(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def already_running(url):
    try:
        with urllib.request.urlopen(url + '/login', timeout=2) as r:
            return r.status < 500
    except Exception:
        return False


def open_browser_when_ready(url):
    def worker():
        for _ in range(60):
            if already_running(url):
                webbrowser.open(url)
                return
            time.sleep(0.5)
    threading.Thread(target=worker, daemon=True).start()


def serve():
    import uvicorn
    from app import create_app, ROOT

    host = os.environ.get('BUS_HOST', '127.0.0.1')
    port = int(os.environ.get('BUS_PORT', '8000'))
    url = f'http://{"127.0.0.1" if host in ("0.0.0.0", "") else host}:{port}'

    if not port_free(host, port):
        if already_running(url):
            print(f'El sistema ya está abierto. Abriendo {url} ...')
            webbrowser.open(url)
            time.sleep(2)
            return
        print(f'El puerto {port} está ocupado por otro programa.')
        print('Cierre ese programa o defina otra variable BUS_PORT (ej. 8080).')
        pause()
        return

    print('=' * 56)
    print('   SISTEMA DE GESTIÓN - COMPAÑÍA DE BUSES')
    print('=' * 56)
    print(f'Datos (base SQLite): {ROOT / "instance" / "buses.sqlite3"}')
    app = create_app()  # crea/actualiza la base y el administrador si no existe
    print(f'\nAbra en su navegador: {url}')
    if NO_CONSOLE:
        print('Para apagar: botón "Apagar sistema" (⏻) en la barra superior (administrador).\n')
    else:
        print('NO cierre esta ventana mientras use el sistema.')
        print('Para apagar el sistema, cierre esta ventana o presione Ctrl+C.\n')
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level='warning',
                                           reload=False, log_config=None))
    # Pequeña espera para que la página de "Sistema apagado" llegue al navegador.
    app.state.shutdown = lambda: threading.Timer(1.0, lambda: setattr(server, 'should_exit', True)).start()
    open_browser_when_ready(url)
    server.run()
    print(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] Sistema apagado.')


def main():
    args = sys.argv[1:]
    if args:
        import manage
        commands = {'init': manage.init, 'demo': manage.demo,
                    'backup': manage.backup, 'reset-admin': manage.reset_admin}
        if args[0] not in commands:
            print(__doc__)
            pause()
            return
        commands[args[0]]()
        pause()
        return
    serve()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        print('\nOcurrió un error al iniciar el sistema.')
        pause()
