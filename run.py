"""Local-only launcher. Use HTTPS reverse proxy and hardened config for external access."""
import os
import uvicorn
from app import create_app

app=create_app()

if __name__=='__main__':
    if not app.state.db.one('SELECT id FROM users LIMIT 1'):
        print('\nNo existe un administrador. Ejecute primero: python manage.py init\n')
    host=os.environ.get('BUS_HOST','127.0.0.1')
    port=int(os.environ.get('BUS_PORT','8000'))
    print(f'\nSistema de Gestión: http://{host}:{port}\n')
    uvicorn.run(app,host=host,port=port,log_level='info',reload=False)
