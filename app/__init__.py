"""BusGestión: FastAPI, SQLite and permissions. Run through run.py."""
import json
import os
import secrets
import sqlite3
from datetime import date
from html import escape
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import Database, PERMISSIONS
from .security import (password_hash,password_ok,password_valid,utcnow,nowstr,token_hash,make_session,
                       locked,register_failure,reset_failures,safe_text,valid_email,valid_username)
from .views import NAV,TABS,TITLES,SUBTITLES,modules
from .forms import PERM_CREATE, spec, save
from .reports import fmt, build_rows, as_csv, as_pdf, REPORT_TYPES

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent/'templates'))
TEMPLATES.env.filters['money'] = fmt

ALLOWED_UPLOADS = {'.pdf':'application/pdf','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg'}

def create_app(db_path=None, testing=False):
    app=FastAPI(title='Sistema de Gestión de Compañía de Buses',docs_url=None,redoc_url=None,openapi_url=None)
    folder=Path(db_path).parent if db_path else ROOT/'instance'
    folder.mkdir(parents=True,exist_ok=True)
    db=Database(db_path or folder/'buses.sqlite3')
    db.init()
    app.state.db=db
    app.state.upload_dir=folder/'uploads'
    app.state.upload_dir.mkdir(exist_ok=True)
    app.state.testing=testing
    app.mount('/static', StaticFiles(directory=str(Path(__file__).resolve().parent/'static')),name='static')

    def current(request):
        return getattr(request.state,'user',None)

    def has(request,perm):
        u=current(request)
        return bool(u and perm in getattr(request.state,'perms',set()))

    def permitted(request,perm=None):
        if not current(request): raise HTTPException(401,'Inicie sesión para continuar.')
        if perm and not has(request,perm): raise HTTPException(403,'No tiene autorización para acceder a este apartado.')
        return current(request)

    def context(request, **more):
        user=current(request)
        return {'request':request,'user':user,'csrf':getattr(request.state,'csrf',''),
                'nav':[{'key':k,'url':url,'icon':icon,'title':label} for k,url,icon,label,p in NAV if not p or has(request,p)],
                'active':more.get('active',''),'ok':request.query_params.get('ok','')[:160],
                'perms':getattr(request.state,'perms',set()),'year':date.today().year,
                'period':db.current_period(),**more}

    def render(request, template, status_code=200,**more):
        return TEMPLATES.TemplateResponse(request,template,context(request,**more),status_code=status_code)

    def redir(url,msg=None):
        sep = '&ok=' if '?' in url else '?ok='
        return RedirectResponse(url+(sep+quote(msg) if msg else ''),status_code=303)

    def parent(kind):
        return {'socios':'/socios','traspasos':'/socios?tab=traspasos','vehiculos':'/unidades?tab=vehiculos','unidades':'/unidades','cambios':'/unidades?tab=cambios',
                'reuniones':'/actas?tab=reuniones','actas':'/actas?tab=actas','convocatorias':'/actas?tab=convocatorias',
                'asistencia':'/actas?tab=asistencia','ingresos':'/finanzas?tab=ingresos','pagos':'/finanzas?tab=pagos',
                'deudas':'/finanzas?tab=deudas','marcaciones':'/finanzas?tab=marcaciones','multas':'/multas',
                'vigilancia':'/vigilancia','usuarios':'/usuarios'}.get(kind,'/')

    async def csrf_check(request):
        fields=await request.form()
        sent=str(fields.get('_csrf',''))
        expected=getattr(request.state,'csrf','')
        if not sent or not expected or not secrets.compare_digest(sent,expected):
            raise HTTPException(403,'Formulario inválido o sesión caducada. Recargue la página y vuelva a intentar.')
        return fields

    def active_period_for_write(con):
        period=Database.ensure_period(con,date.today())
        if period['closed_at']:
            raise ValueError('El periodo ya está cerrado.')
        return period

    def client_ip(request: Request) -> str:
        xff = request.headers.get('x-forwarded-for')
        if xff:
            return xff.split(',')[0].strip()
        return request.client.host if (request.client and request.client.host) else '127.0.0.1'

    @app.middleware('http')
    async def security_middleware(request, call_next):
        # Uploaded static content is served without sessions; any confidential file uses its own authenticated route.
        if request.url.path.startswith('/static/'):
            response=await call_next(request)
        else:
            token=request.cookies.get('bus_sid','')
            row=db.one('''SELECT s.token_hash,s.user_id,s.csrf,s.version,s.expires_at,
                             u.username,u.full_name,u.role_id,u.active,u.socio_id,u.session_version,r.name AS role
                         FROM sessions s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN roles r ON r.id=u.role_id
                         WHERE s.token_hash=?''',(token_hash(token),)) if token else None
            valid=row and row['expires_at']>nowstr() and (row['user_id'] is None or (row['active'] and row['version']==row['session_version']))
            if valid:
                request.state.csrf=row['csrf']
                request.state.sid_hash=row['token_hash']
                if row['user_id']:
                    request.state.user={k:row[k] for k in ('user_id','username','full_name','role_id','socio_id','role')}
                    request.state.user['id']=row['user_id']
                    request.state.perms={x['permission'] for x in db.all('SELECT permission FROM role_permissions WHERE role_id=?',(row['role_id'],))}
                else:
                    request.state.user=None;request.state.perms=set()
                request.state.cookie_to_set=None
            else:
                with db.connection() as con:
                    token,csrf=make_session(con)
                request.state.csrf=csrf
                request.state.sid_hash=token_hash(token)
                request.state.user=None;request.state.perms=set()
                request.state.cookie_to_set=token
            request.state.clear_cookie=False
            response=await call_next(request)
            if request.state.clear_cookie:
                response.delete_cookie('bus_sid',path='/')
            else:
                fresh=getattr(request.state,'cookie_to_set',None)
                if fresh:
                    response.set_cookie('bus_sid',fresh,max_age=8*3600,httponly=True,samesite='lax',
                                        secure=os.environ.get('BUS_HTTPS','0')=='1',path='/')
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        if not request.url.path.startswith('/static/'):
            response.headers['Cache-Control']='no-store'
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if exc.status_code==401:
            return redir('/login')
        return render(request,'error.html',status_code=exc.status_code,code=exc.status_code,message=exc.detail)

    @app.exception_handler(404)
    async def missing_route(request,exc):
        return render(request,'error.html',status_code=404,code=404,message='La página solicitada no existe.')

    @app.get('/login',response_class=HTMLResponse)
    def login_page(request:Request):
        if current(request):return redir('/')
        return render(request,'login.html',error=None)

    @app.post('/login')
    async def login(request:Request):
        f=await csrf_check(request)
        username=str(f.get('username','')).strip().lower()
        pwd=str(f.get('password',''))
        ip=client_ip(request)
        with db.connection() as con:
            if locked(con,username,ip):
                Database.audit(con,None,'Bloqueo temporal','autenticacion',None,f"Acceso temporalmente bloqueado para '{username}' desde IP {ip} por 15 minutos", ip=ip)
                return render(request,'login.html',status_code=429,error='Demasiados intentos. Inténtelo nuevamente en 15 minutos.')
            u=con.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
            if not u or not u['active'] or not password_ok(pwd,u['password_hash']):
                register_failure(con,username,ip)
                Database.audit(con,u['id'] if u else None,'Intento fallido','autenticacion',None,f"Intento de acceso fallido con usuario '{username}' desde IP {ip}", ip=ip)
                return render(request,'login.html',status_code=401,error='Usuario o contraseña incorrectos.')
            reset_failures(con,username,ip)
            con.execute('DELETE FROM sessions WHERE token_hash=?',(request.state.sid_hash,))
            token,csrf=make_session(con,u['id'],u['session_version'])
            Database.audit(con,u['id'],'Inicio de sesión','autenticacion',u['id'],f"Inicio de sesión exitoso de '{u['username']}' ({u['full_name']}) desde IP {ip}", ip=ip)
        request.state.cookie_to_set=token
        return redir('/')

    @app.get('/recuperar')
    def recover_page(request:Request):
        return render(request,'recover.html',sent=False)

    @app.post('/recuperar')
    async def recover(request:Request):
        f=await csrf_check(request)
        username=str(f.get('username','')).strip().lower()
        ip=client_ip(request)
        with db.connection() as con:
            Database.audit(con,None,'Recuperar clave','autenticacion',None,f"Solicitud de recuperación para '{username}' desde IP {ip}", ip=ip)
        # Intentionally do not disclose whether a user exists. Local version has no outgoing email service.
        return render(request,'recover.html',sent=True)

    @app.post('/logout')
    async def logout(request:Request):
        await csrf_check(request)
        ip=client_ip(request)
        with db.connection() as con:
            user = current(request)
            if user:
                Database.audit(con,user['id'],'Cierre de sesión','autenticacion',user['id'],f"Cierre de sesión del usuario '{user['username']}'", ip=ip)
            con.execute('DELETE FROM sessions WHERE token_hash=?',(request.state.sid_hash,))
        request.state.clear_cookie=True
        return redir('/login')

    @app.get('/perfil')
    def profile(request:Request):
        permitted(request)
        return render(request,'profile.html',active='perfil',error=None)

    @app.post('/perfil')
    async def change_password(request:Request):
        u=permitted(request)
        f=await csrf_check(request)
        old=str(f.get('actual','')); new=str(f.get('nueva','')); again=str(f.get('confirmar',''))
        stored=db.one('SELECT password_hash FROM users WHERE id=?',(u['id'],))
        if not password_ok(old,stored['password_hash']) or not password_valid(new) or new!=again:
            return render(request,'profile.html',active='perfil',error='Revise la contraseña actual, el mínimo de 12 caracteres y la confirmación.',status_code=400)
        ip=client_ip(request)
        with db.connection() as con:
            con.execute('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',(password_hash(new),u['id']))
            con.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
            Database.audit(con,u['id'],'Cambiar contraseña','usuarios',u['id'],f"El usuario '{u['username']}' cambió su contraseña", ip=ip)
        request.state.clear_cookie=True
        return redir('/login','Contraseña actualizada. Inicie sesión nuevamente.')

    @app.get('/')
    def dashboard(request:Request):
        permitted(request)
        user=current(request)
        own=user['role']=='Socio'
        condition=' WHERE socio_id=?' if own else ''
        args=(user['socio_id'],) if own else ()
        soc=db.one('SELECT COUNT(*) n FROM socios WHERE active=1')['n']
        units=db.one('SELECT COUNT(*) n FROM units')['n']
        debts=db.one('SELECT COALESCE(SUM(amount_cents-paid_cents),0) n FROM debts'+condition,args)['n']
        fines=db.one('SELECT COUNT(*) n FROM fines'+condition,args)['n']
        meetings=db.one('SELECT COUNT(*) n FROM meetings WHERE meeting_date >=?', (date.today().isoformat(),))['n']
        period=db.current_period()
        inc=db.one('SELECT COALESCE(SUM(amount_cents),0) n FROM incomes WHERE period_id=?'+(' AND socio_id=?' if own else ''),(period['id'],)+args)['n']
        pays=db.one('SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE period_id=?'+(' AND socio_id=?' if own else ''),(period['id'],)+args)['n']
        cards=[{'label':'Ingresos del periodo','value':fmt(inc+pays),'icon':'▥','color':'green'},
               {'label':'Deudas pendientes','value':fmt(debts),'icon':'◇','color':'red'},
               {'label':'Multas registradas','value':fines,'icon':'⚒','color':'orange'},
               {'label':'Reuniones próximas','value':meetings,'icon':'▤','color':'purple'}]
        latest=db.all('SELECT created_at,entity,action,summary FROM audit ORDER BY id DESC LIMIT 8') if has(request,'auditoria.ver') else []
        next_meetings=db.all('SELECT meeting_date,meeting_time,type,topic FROM meetings WHERE meeting_date>=? ORDER BY meeting_date LIMIT 5',(date.today().isoformat(),))
        topdebts=db.all('SELECT s.name,COALESCE(SUM(d.amount_cents-d.paid_cents),0) pending FROM debts d JOIN socios s ON s.id=d.socio_id WHERE d.amount_cents>d.paid_cents'+(' AND d.socio_id=?' if own else '')+' GROUP BY s.id ORDER BY pending DESC LIMIT 6',args)
        monthly=db.all('SELECT substr(day,1,7) month,SUM(amount_cents) amount FROM incomes WHERE period_id=?'+(' AND socio_id=?' if own else '')+' GROUP BY substr(day,1,7) ORDER BY month LIMIT 12',(period['id'],)+args)
        return render(request,'dashboard.html',active='dashboard',cards=cards,topdebts=topdebts,latest=latest,
                      next_meetings=next_meetings,monthly=monthly,socios_count=soc,units_count=units,fmt=fmt)

    def get_socio_unit_data():
        socios = db.all("""
            SELECT 
                s.id AS socio_id,
                s.name,
                COALESCE(s.cedula, '') AS cedula,
                COALESCE(s.phone, '') AS phone,
                s.active,
                u.id AS unit_id,
                COALESCE(u.code, '') AS unit_code,
                COALESCE(v.plate, '') AS plate
            FROM socios s
            LEFT JOIN units u ON u.socio_id = s.id AND u.status = 'Activa'
            LEFT JOIN vehicles v ON v.id = u.vehicle_id
            WHERE s.active = 1
            ORDER BY s.name
        """)
        units = db.all("""
            SELECT 
                u.id AS unit_id,
                u.code AS unit_code,
                u.status AS unit_status,
                s.id AS socio_id,
                COALESCE(s.name, 'Sin socio asignado') AS socio_name,
                COALESCE(s.cedula, '') AS cedula,
                COALESCE(v.plate, '') AS plate
            FROM units u
            LEFT JOIN socios s ON s.id = u.socio_id
            LEFT JOIN vehicles v ON v.id = u.vehicle_id
            ORDER BY u.code
        """)
        return socios, units

    @app.get('/api/lookup-socio-unit')
    def api_lookup_socio_unit(request: Request, q: str = ''):
        permitted(request)
        q = q.strip()
        if not q:
            return JSONResponse([])
        rows = db.all("""
            SELECT 
                s.id AS socio_id,
                s.name,
                COALESCE(s.cedula, '') AS cedula,
                COALESCE(s.phone, '') AS phone,
                u.id AS unit_id,
                COALESCE(u.code, '') AS unit_code,
                COALESCE(v.plate, '') AS plate
            FROM socios s
            LEFT JOIN units u ON u.socio_id = s.id AND u.status = 'Activa'
            LEFT JOIN vehicles v ON v.id = u.vehicle_id
            WHERE s.cedula LIKE ? OR u.code LIKE ? OR s.name LIKE ?
            LIMIT 15
        """, (f'%{q}%', f'%{q}%', f'%{q}%'))
        return JSONResponse(rows)

    @app.get('/nuevo/{kind}')
    def new_form(request:Request,kind:str):
        if kind=='convocatorias':
            mid=request.query_params.get('meeting_id','')
            return redir('/actas?tab=convocatorias'+(f'&meeting_id={mid}' if mid else ''))
        permitted(request,PERM_CREATE.get(kind,'__no__'))
        s=spec(db,kind)
        initial={'joined':date.today().isoformat(),'meeting_date':date.today().isoformat(),'day':date.today().isoformat(),
                 'issued':date.today().isoformat(),'occurred_at':date.today().isoformat(),'week_start':date.today().isoformat(),
                 'changed_at':date.today().isoformat(),'transferred_at':date.today().isoformat()}
        socios_l, units_l = get_socio_unit_data()
        return render(request,'form.html',active='',form=s,values=initial,error=None,cancel=parent(kind),editing=False,
                      socio_lookup=socios_l,unit_lookup=units_l,socio_lookup_json=json.dumps(socios_l),unit_lookup_json=json.dumps(units_l))

    @app.post('/nuevo/{kind}')
    async def new_save(request:Request,kind:str):
        permitted(request,PERM_CREATE.get(kind,'__no__'))
        fields=await csrf_check(request)
        values={k:str(v) for k,v in fields.items() if k!='_csrf'}
        try:
            save(db,kind,values,current(request)['id'],ip=client_ip(request))
        except (ValueError,sqlite3.IntegrityError) as exc:
            msg='No se pudo guardar: ya existe un registro igual o faltan datos válidos.' if isinstance(exc,sqlite3.IntegrityError) else str(exc)
            socios_l, units_l = get_socio_unit_data()
            return render(request,'form.html',status_code=400,active='',form=spec(db,kind),values=values,error=msg,cancel=parent(kind),editing=False,
                          socio_lookup=socios_l,unit_lookup=units_l,socio_lookup_json=json.dumps(socios_l),unit_lookup_json=json.dumps(units_l))
        message='Traspaso registrado; propietario e historial actualizados.' if kind=='traspasos' else 'Registro guardado correctamente.'
        return redir(parent(kind),message)

    EDITABLE={'socios':('socios','socios.crear'), 'vehiculos':('vehicles','unidades.editar'),
              'unidades':('units','unidades.editar'), 'reuniones':('meetings','actas.editar')}
    EDIT_KEYS={'socios':{'name':'name','cedula':'cedula','phone':'phone','email':'email','joined':'joined','notes':'notes'},
               'vehiculos':{'plate':'plate','brand':'brand','model':'model','year':'year','status':'status'},
               'unidades':{'code':'code','socio_id':'socio_id','vehicle_id':'vehicle_id','status':'status'},
               'reuniones':{'type':'type','topic':'topic','meeting_date':'meeting_date','meeting_time':'meeting_time','location':'location','agenda':'agenda'}}

    @app.get('/editar/{kind}/{record_id}')
    def edit_form(request:Request,kind:str,record_id:int):
        permitted(request,EDITABLE.get(kind,('', '__no__'))[1])
        table=EDITABLE[kind][0]
        item=db.one(f'SELECT * FROM {table} WHERE id=?',(record_id,))
        if not item:raise HTTPException(404,'Registro no encontrado.')
        socios_l, units_l = get_socio_unit_data()
        return render(request,'form.html',active='',form=spec(db,kind),values={f:str(item[column] or '') for f,column in EDIT_KEYS[kind].items()},error=None,cancel=parent(kind),editing=True,record_id=record_id,
                      socio_lookup=socios_l,unit_lookup=units_l,socio_lookup_json=json.dumps(socios_l),unit_lookup_json=json.dumps(units_l))

    @app.post('/editar/{kind}/{record_id}')
    async def edit_save(request:Request,kind:str,record_id:int):
        permitted(request,EDITABLE.get(kind,('', '__no__'))[1])
        f=await csrf_check(request)
        v={k:str(val) for k,val in f.items() if k!='_csrf'}
        try:save(db,kind,v,current(request)['id'],record_id,ip=client_ip(request))
        except (ValueError,sqlite3.IntegrityError) as exc:
            socios_l, units_l = get_socio_unit_data()
            return render(request,'form.html',active='',form=spec(db,kind),values=v,error=str(exc),cancel=parent(kind),editing=True,record_id=record_id,status_code=400,
                          socio_lookup=socios_l,unit_lookup=units_l,socio_lookup_json=json.dumps(socios_l),unit_lookup_json=json.dumps(units_l))
        return redir(parent(kind),'Cambios guardados.')

    @app.post('/permisos/{role_id}')
    async def save_permissions(request:Request,role_id:int):
        permitted(request,'roles.editar')
        f=await csrf_check(request)
        role=db.one('SELECT * FROM roles WHERE id=?',(role_id,))
        if not role:raise HTTPException(404,'Rol no encontrado.')
        if role['name']=='Administrador':raise HTTPException(403,'Los permisos del administrador principal no pueden modificarse.')
        checked=set(f.getlist('permissions'))
        if not checked.issubset(set(PERMISSIONS)):raise HTTPException(400,'Permisos desconocidos.')
        # A Socio cannot receive permissions allowing access to the company's confidential information.
        if role['name']=='Socio' and checked-{'actas.ver','finanzas.ver','multas.ver','unidades.ver'}:
            raise HTTPException(400,'El rol Socio solo permite consulta de su información y actas.')
        ip=client_ip(request)
        with db.connection() as con:
            con.execute('DELETE FROM role_permissions WHERE role_id=?',(role_id,))
            for p in checked:con.execute('INSERT INTO role_permissions(role_id,permission) VALUES(?,?)',(role_id,p))
            con.execute('UPDATE users SET session_version=session_version+1 WHERE role_id=?',(role_id,))
            Database.audit(con,current(request)['id'],'Actualizar permisos','permisos',role_id,f"Permisos actualizados para el rol '{role['name']}' ({len(checked)} permisos)", ip=ip)
        return redir('/usuarios?tab=permisos','Permisos actualizados.')

    @app.post('/usuarios/{user_id}/estado')
    async def state_user(request:Request,user_id:int):
        permitted(request,'usuarios.editar')
        await csrf_check(request)
        user=db.one('SELECT u.*,r.name AS role FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?',(user_id,))
        if not user:raise HTTPException(404,'Usuario no encontrado.')
        if user_id==current(request)['id']:raise HTTPException(400,'No puede desactivar su propia cuenta.')
        if user['role']=='Administrador' and user['active'] and db.one('SELECT COUNT(*) n FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name=? AND u.active=1',('Administrador',))['n']<=1:
            raise HTTPException(400,'Debe existir al menos un administrador activo.')
        ip=client_ip(request)
        with db.connection() as con:
            con.execute('UPDATE users SET active=?,session_version=session_version+1 WHERE id=?',(0 if user['active'] else 1,user_id))
            con.execute('DELETE FROM sessions WHERE user_id=?',(user_id,))
            Database.audit(con,current(request)['id'],'Cambiar estado','usuarios',user_id,f"Usuario '{user['username']}' cambiado a {'Inactivo' if user['active'] else 'Activo'}", ip=ip)
        return redir('/usuarios','Estado actualizado.')

    @app.post('/usuarios/{user_id}/reiniciar-clave')
    async def reset_password(request:Request,user_id:int):
        permitted(request,'usuarios.editar')
        await csrf_check(request)
        u=db.one('SELECT id,username FROM users WHERE id=?',(user_id,))
        if not u:raise HTTPException(404,'Usuario no encontrado.')
        new_secret=secrets.token_urlsafe(18)
        ip=client_ip(request)
        with db.connection() as con:
            con.execute('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',(password_hash(new_secret),user_id))
            con.execute('DELETE FROM sessions WHERE user_id=?',(user_id,))
            Database.audit(con,current(request)['id'],'Restablecer clave','usuarios',user_id,f"Clave temporal generada para el usuario '{u['username']}'", ip=ip)
        return render(request,'one_time_secret.html',active='usuarios',account=u['username'],secret=new_secret)

    @app.post('/multas/{fine_id}/anular')
    async def void_fine(request:Request,fine_id:int):
        permitted(request,'multas.editar');await csrf_check(request)
        ip=client_ip(request)
        with db.connection() as con:
            period=active_period_for_write(con)
            fine=con.execute('SELECT * FROM fines WHERE id=?',(fine_id,)).fetchone()
            if not fine or fine['status']!='Pendiente' or fine['period_id']!=period['id']:
                raise HTTPException(400,'Solo se pueden anular multas pendientes del periodo abierto.')
            debt=con.execute('SELECT * FROM debts WHERE fine_id=?',(fine_id,)).fetchone()
            if debt and debt['paid_cents']:
                raise HTTPException(400,'No se puede anular una multa con pagos aplicados.')
            con.execute('DELETE FROM debts WHERE fine_id=?',(fine_id,))
            con.execute("UPDATE fines SET status='Anulada' WHERE id=?",(fine_id,))
            Database.audit(con,current(request)['id'],'Anular multa','multas',fine_id,f"Multa ID {fine_id} anulada (Motivo: {fine['reason']})", ip=ip)
        return redir('/multas','Multa anulada con registro de auditoría.')

    @app.post('/actas/{meeting_id}/archivo')
    async def upload_acta(request:Request,meeting_id:int):
        permitted(request,'actas.editar')
        f=await csrf_check(request)
        file=f.get('archivo')
        if not file or not hasattr(file,'filename') or not file.filename:
            raise HTTPException(400,'Seleccione un archivo PDF o imagen.')
        ext=Path(file.filename).suffix.lower()
        if ext not in ALLOWED_UPLOADS:raise HTTPException(400,'Formato no permitido.')
        data=await file.read(5*1024*1024+1)
        if len(data)>5*1024*1024: raise HTTPException(413,'Máximo 5 MB por archivo.')
        is_pdf=data.startswith(b'%PDF-');is_png=data.startswith(b'\x89PNG\r\n\x1a\n');is_jpg=data.startswith(b'\xff\xd8\xff')
        if not (is_pdf if ext=='.pdf' else is_png if ext=='.png' else is_jpg):
            raise HTTPException(400,'El contenido del archivo no coincide con su extensión.')
        if not db.one('SELECT id FROM meetings WHERE id=?',(meeting_id,)):
            raise HTTPException(404,'Reunión no encontrada.')
        safe=secrets.token_hex(24)+ext
        target=app.state.upload_dir/safe
        target.write_bytes(data)
        ip=client_ip(request)
        try:
            with db.connection() as con:
                rid=con.execute('INSERT INTO docs(meeting_id,filename,safe_path,kind,uploaded_by) VALUES(?,?,?,?,?)',(meeting_id,Path(file.filename).name[:120],safe,'acta',current(request)['id'])).lastrowid
                Database.audit(con,current(request)['id'],'Adjuntar acta','actas',meeting_id,f"Archivo '{Path(file.filename).name}' subido a reunión ID {meeting_id}", ip=ip)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        return redir('/actas?tab=actas','Archivo adjuntado.')

    @app.get('/archivos/{doc_id}')
    def download_document(request:Request,doc_id:int):
        permitted(request,'actas.ver')
        document=db.one('SELECT * FROM docs WHERE id=?',(doc_id,))
        if not document:raise HTTPException(404,'Documento no encontrado.')
        file=app.state.upload_dir/document['safe_path']
        if not file.is_file():raise HTTPException(404,'Archivo no disponible.')
        return FileResponse(str(file),filename=document['filename'],media_type=ALLOWED_UPLOADS.get(file.suffix,'.pdf'))

    @app.get('/reporte/{kind}.{format}')
    def download_report(request:Request,kind:str,format:str,period_id:int=0):
        permitted(request,'reportes.ver')
        if kind in REPORT_TYPES:permitted(request,'reportes.'+kind)
        if kind not in REPORT_TYPES or format not in ('pdf','csv'):raise HTTPException(404,'Tipo de reporte no disponible.')
        period=db.one('SELECT * FROM periods WHERE id=?',(period_id,)) if period_id else db.current_period()
        if not period:raise HTTPException(404,'Periodo no encontrado.')
        heads,rows=build_rows(db,kind,period['id'])
        blob=as_pdf(REPORT_TYPES[kind],period,heads,rows) if format=='pdf' else as_csv(heads,rows)
        filename=f'reporte_{kind}_{period["label"]}.{format}'
        med='application/pdf' if format=='pdf' else 'text/csv; charset=utf-8'
        return Response(blob,media_type=med,headers={'Content-Disposition':f'attachment; filename="{filename}"'})

    @app.post('/cierre')
    async def close_year(request:Request):
        permitted(request,'cierres.ejecutar')
        f=await csrf_check(request)
        currentp=db.current_period()
        expected='CERRAR '+currentp['label']
        if str(f.get('confirmacion','')).strip()!=expected:
            raise HTTPException(400,f'Para confirmar escriba exactamente: {expected}')
        if date.today()<date.fromisoformat(currentp['ends']):
            raise HTTPException(400,'El cierre real solo puede ejecutarse desde el 25 de diciembre. Mientras tanto puede descargar reportes de prueba.')
        with db.connection() as con:
            p=con.execute('SELECT * FROM periods WHERE id=?',(currentp['id'],)).fetchone()
            if not p or p['closed_at']:raise HTTPException(400,'El periodo ya está cerrado.')
            headers,rows=build_rows(db,'general',p['id'])
            snapshot=json.dumps(dict(zip([r[0] for r in rows],[r[1] for r in rows])),ensure_ascii=False)
            con.execute('UPDATE periods SET closed_at=CURRENT_TIMESTAMP,closed_by=?,snapshot=? WHERE id=?',(current(request)['id'],snapshot,p['id']))
            Database.audit(con,current(request)['id'],'Cierre anual','periodos',p['id'],f"Cierre del periodo anual {p['label']}", ip=client_ip(request))
        return redir('/reportes?tab=cierre','Cierre anual completado. Los datos históricos permanecen disponibles.')

    @app.get('/buscar')
    def search(request:Request,q:str=''):
        permitted(request)
        q=q.strip()[:80]
        result=[]
        if q:
            if has(request,'socios.ver'):
                result += [{'title':'Socio: '+r['name'],'detail':r['cedula'] or '', 'url':'/socios'} for r in db.all('SELECT name,cedula FROM socios WHERE name LIKE ? OR cedula LIKE ? LIMIT 12',('%'+q+'%','%'+q+'%'))]
            if has(request,'actas.ver'):
                result += [{'title':'Reunión: '+r['topic'],'detail':r['meeting_date'],'url':'/actas?tab=reuniones'} for r in db.all('SELECT topic,meeting_date FROM meetings WHERE topic LIKE ? LIMIT 12',('%'+q+'%',))]
            if has(request,'unidades.ver') and current(request)['role']!='Socio':
                result += [{'title':'Unidad: '+r['code'],'detail':r['status'],'url':'/unidades'} for r in db.all('SELECT code,status FROM units WHERE code LIKE ? LIMIT 12',('%'+q+'%',))]
            if has(request,'auditoria.ver'):
                result += [{'title':'Historial: '+r['action'],'detail':f"{r['created_at']} - {r['summary'][:60]}",'url':'/auditoria'} for r in db.all('SELECT action,created_at,summary FROM audit WHERE summary LIKE ? OR action LIKE ? LIMIT 12',('%'+q+'%','%'+q+'%'))]
        return render(request,'search.html',active='',results=result,q=q)


    @app.get('/reunion/{meeting_id}')
    def meeting_detail(request:Request,meeting_id:int):
        permitted(request,'actas.ver')
        m=db.one('SELECT * FROM meetings WHERE id=?',(meeting_id,))
        if not m:raise HTTPException(404,'Reunión no encontrada.')
        docs=db.all('SELECT id,filename,uploaded_at FROM docs WHERE meeting_id=? ORDER BY id DESC',(meeting_id,))
        attendance=db.all('SELECT s.name,a.status,a.socio_id FROM attendance a JOIN meetings m ON m.id=a.meeting_id JOIN socios s ON s.id=a.socio_id WHERE m.id=? ORDER BY s.name',(meeting_id,))
        if current(request)['role']=='Socio':
            attendance=[r for r in attendance if r['socio_id']==current(request)['socio_id']]
        notif_counts = db.one('''
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN notified=1 THEN 1 ELSE 0 END), 0) AS notificados
            FROM meeting_notifications WHERE meeting_id=?
        ''', (meeting_id,))
        return render(request,'meeting.html',active='actas',m=m,docs=docs,attendance=attendance,
                      can_manage=has(request,'actas.editar'),notif_counts=notif_counts)

    @app.post('/reunion/{meeting_id}/realizada')
    async def complete_meeting(request:Request,meeting_id:int):
        permitted(request,'actas.editar');await csrf_check(request)
        with db.connection() as con:
            m=con.execute('SELECT topic FROM meetings WHERE id=?',(meeting_id,)).fetchone()
            if not m:
                raise HTTPException(404,'Reunión no encontrada.')
            con.execute("UPDATE meetings SET status='Realizada' WHERE id=?",(meeting_id,))
            Database.audit(con,current(request)['id'],'Reunión realizada','reuniones',meeting_id,f"Reunión ID {meeting_id} '{m['topic']}' marcada como realizada", ip=client_ip(request))
        return redir('/reunion/'+str(meeting_id),'Reunión marcada como realizada.')

    @app.get('/usuario/{user_id}')
    def user_detail(request:Request,user_id:int):
        permitted(request,'usuarios.ver')
        target=db.one('SELECT u.*,r.name AS role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?',(user_id,))
        if not target:raise HTTPException(404,'Usuario no encontrado.')
        roles=db.all('SELECT * FROM roles ORDER BY id')
        events=db.all('SELECT action,entity,created_at FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 20',(user_id,)) if has(request,'auditoria.ver') else []
        return render(request,'user_detail.html',active='usuarios',target=target,roles=roles,events=events,can_manage=has(request,'usuarios.editar'))

    @app.post('/usuario/{user_id}/rol')
    async def change_user_role(request:Request,user_id:int):
        permitted(request,'usuarios.editar')
        f=await csrf_check(request)
        try:role_id=int(str(f.get('role_id','')))
        except ValueError:raise HTTPException(400,'Rol inválido.')
        role=db.one('SELECT * FROM roles WHERE id=?',(role_id,))
        user=db.one('SELECT * FROM users WHERE id=?',(user_id,))
        if not user or not role:raise HTTPException(404,'Usuario o rol no encontrado.')
        if user['id']==current(request)['id']:
            raise HTTPException(400,'No puede cambiar su propio rol.')
        current_role=db.one('SELECT name FROM roles WHERE id=?',(user['role_id'],))
        if current_role['name']=='Administrador' and role['name']!='Administrador':
            active_admin=db.one("SELECT COUNT(*) n FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='Administrador' AND u.active=1")['n']
            if active_admin<=1:raise HTTPException(400,'Debe conservar al menos un administrador activo.')
        if role['name']=='Socio' and not user['socio_id']:
            raise HTTPException(400,'Para asignar el rol Socio, la cuenta debe estar vinculada a un socio.')
        with db.connection() as con:
            con.execute('UPDATE users SET role_id=?,session_version=session_version+1 WHERE id=?',(role_id,user_id))
            con.execute('DELETE FROM sessions WHERE user_id=?',(user_id,))
            Database.audit(con,current(request)['id'],'Cambiar rol','usuarios',user_id,f"Rol de '{user['username']}' cambiado de '{current_role['name']}' a '{role['name']}'", ip=client_ip(request))
        return redir('/usuario/'+str(user_id),'Rol actualizado y sesiones anteriores invalidadas.')

    @app.post('/actas/asistencia')
    async def save_attendance_batch(request: Request):
        permitted(request, 'actas.editar')
        f = await csrf_check(request)
        try:
            meeting_id = int(str(f.get('meeting_id', '')).strip())
        except ValueError:
            raise HTTPException(400, 'Reunión no válida.')
        meeting = db.one('SELECT * FROM meetings WHERE id=?', (meeting_id,))
        if not meeting:
            raise HTTPException(404, 'Reunión no encontrada.')

        all_socio_ids = [int(x) for x in f.getlist('all_socio_ids') if str(x).isdigit()]
        if not all_socio_ids:
            db_socios = db.all('''
                SELECT s.id FROM socios s
                LEFT JOIN attendance a ON a.socio_id=s.id AND a.meeting_id=?
                WHERE s.active=1 OR a.meeting_id IS NOT NULL
            ''', (meeting_id,))
            all_socio_ids = [s['id'] for s in db_socios]

        checked_socio_ids = {int(x) for x in f.getlist('asistio_ids') if str(x).isdigit()}

        with db.connection() as con:
            for sid in all_socio_ids:
                status = 'Asistió' if sid in checked_socio_ids else 'Faltó'
                con.execute('''
                    INSERT INTO attendance(meeting_id, socio_id, status)
                    VALUES(?, ?, ?)
                    ON CONFLICT(meeting_id, socio_id) DO UPDATE SET status=excluded.status
                ''', (meeting_id, sid, status))
            Database.audit(con, current(request)['id'], 'Guardar asistencia', 'asistencia', meeting_id,
                           f'Asistencia reunión {meeting_id}: {len(checked_socio_ids)} de {len(all_socio_ids)} convocados', ip=client_ip(request))

        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or 'application/json' in request.headers.get('accept', ''):
            return JSONResponse({'ok': True, 'message': 'Asistencia guardada correctamente.', 'meeting_id': meeting_id})

        return redir(f'/actas?tab=asistencia&meeting_id={meeting_id}', 'Asistencia guardada correctamente.')

    @app.post('/actas/convocatoria')
    async def save_convocatoria_batch(request: Request):
        permitted(request, 'actas.editar')
        f = await csrf_check(request)
        try:
            meeting_id = int(str(f.get('meeting_id', '')).strip())
        except ValueError:
            raise HTTPException(400, 'Reunión no válida.')
        meeting = db.one('SELECT * FROM meetings WHERE id=?', (meeting_id,))
        if not meeting:
            raise HTTPException(404, 'Reunión no encontrada.')

        notice = str(f.get('notice', '')).strip()
        all_socio_ids = [int(x) for x in f.getlist('all_socio_ids') if str(x).isdigit()]
        if not all_socio_ids:
            db_socios = db.all('''
                SELECT s.id FROM socios s
                LEFT JOIN meeting_notifications mn ON mn.socio_id=s.id AND mn.meeting_id=?
                WHERE s.active=1 OR mn.meeting_id IS NOT NULL
            ''', (meeting_id,))
            all_socio_ids = [s['id'] for s in db_socios]

        notified_ids = {int(x) for x in f.getlist('notified_ids') if str(x).isdigit()}

        with db.connection() as con:
            con.execute("UPDATE meetings SET notice=?, notice_sent_at=COALESCE(notice_sent_at, CURRENT_TIMESTAMP) WHERE id=?",
                        (notice, meeting_id))
            now_iso = nowstr()
            for sid in all_socio_ids:
                is_notif = 1 if sid in notified_ids else 0
                notif_time = now_iso if is_notif else None
                con.execute('''
                    INSERT INTO meeting_notifications(meeting_id, socio_id, notified, notified_at)
                    VALUES(?, ?, ?, ?)
                    ON CONFLICT(meeting_id, socio_id) DO UPDATE SET
                      notified = excluded.notified,
                      notified_at = excluded.notified_at
                ''', (meeting_id, sid, is_notif, notif_time))
            Database.audit(con, current(request)['id'], 'Guardar convocatoria', 'convocatorias', meeting_id,
                           f'Convocatoria reunión {meeting_id}: {len(notified_ids)} notificados de {len(all_socio_ids)} convocados', ip=client_ip(request))

        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or 'application/json' in request.headers.get('accept', ''):
            return JSONResponse({'ok': True, 'message': 'Convocatoria y notificaciones guardadas correctamente.', 'meeting_id': meeting_id})

        return redir(f'/actas?tab=convocatorias&meeting_id={meeting_id}', 'Convocatoria y notificaciones guardadas correctamente.')

    @app.get('/{module_name}')
    def module_page(request:Request,module_name:str,tab:str=''):
        # Keep this generic module route last among GET routes to avoid collisions.
        if module_name not in TABS: raise HTTPException(404,'Módulo no encontrado.')
        perm={'socios':'socios.ver','actas':'actas.ver','finanzas':'finanzas.ver','multas':'multas.ver',
              'unidades':'unidades.ver','vigilancia':'vigilancia.ver','reportes':'reportes.ver','usuarios':'usuarios.ver','auditoria':'auditoria.ver'}[module_name]
        permitted(request,perm)
        if module_name=='auditoria' and current(request)['role']!='Administrador':
            raise HTTPException(403,'Apartado reservado exclusivamente para el Administrador.')
        if not tab or tab not in dict(TABS[module_name]): tab=TABS[module_name][0][0]
        u=current(request)
        data=modules(db,module_name,tab,u['role'],u['socio_id'])
        if data.get('new_kind') and not has(request,PERM_CREATE[data['new_kind']]):data['new_kind']=None
        if module_name=='usuarios' and tab=='permisos':
            data['permission_labels']=PERMISSIONS
            data['selected_role_permissions']={role['id']:{x['permission'] for x in db.all('SELECT permission FROM role_permissions WHERE role_id=?',(role['id'],))} for role in data['role_rows']}
        
        extra = {}
        if module_name=='actas' and tab=='asistencia':
            meetings = db.all('SELECT id, type, topic, meeting_date, meeting_time, status FROM meetings ORDER BY meeting_date DESC, id DESC')
            selected_meeting_id = None
            raw_mid = request.query_params.get('meeting_id')
            if raw_mid and raw_mid.isdigit():
                mid_int = int(raw_mid)
                if any(m['id'] == mid_int for m in meetings):
                    selected_meeting_id = mid_int
            selected_meeting = db.one('SELECT * FROM meetings WHERE id=?', (selected_meeting_id,)) if selected_meeting_id else None

            socios_attendance = []
            summary = None
            if selected_meeting:
                m_socios = db.all('''
                    SELECT s.id, s.name,
                           (SELECT GROUP_CONCAT(u.code, ', ') FROM units u WHERE u.socio_id=s.id) AS unit_code,
                           a.status AS attendance_status
                    FROM socios s
                    LEFT JOIN attendance a ON a.socio_id = s.id AND a.meeting_id = ?
                    WHERE s.active = 1 OR a.meeting_id IS NOT NULL
                    ORDER BY s.name ASC
                ''', (selected_meeting_id,))
                convocados_cnt = len(m_socios)
                asistentes_cnt = sum(1 for s in m_socios if s['attendance_status'] == 'Asistió')
                socios_attendance = [
                    {
                        'id': s['id'],
                        'name': s['name'],
                        'unit_code': s['unit_code'] or '—',
                        'asistio': s['attendance_status'] == 'Asistió'
                    }
                    for s in m_socios
                ]
                summary = {
                    'convocados': convocados_cnt,
                    'asistentes': asistentes_cnt,
                    'ausentes': convocados_cnt - asistentes_cnt
                }

            extra.update(
                can_manage_attendance=has(request, 'actas.editar'),
                meetings=meetings,
                selected_meeting=selected_meeting,
                socios_attendance=socios_attendance,
                summary=summary
            )

        if module_name=='actas' and tab=='convocatorias':
            meetings = db.all('SELECT id, type, topic, meeting_date, meeting_time, location, agenda, status, notice, notice_sent_at FROM meetings ORDER BY meeting_date DESC, id DESC')
            selected_meeting_id = None
            raw_mid = request.query_params.get('meeting_id')
            if raw_mid and raw_mid.isdigit():
                mid_int = int(raw_mid)
                if any(m['id'] == mid_int for m in meetings):
                    selected_meeting_id = mid_int
            selected_meeting = db.one('SELECT * FROM meetings WHERE id=?', (selected_meeting_id,)) if selected_meeting_id else None

            socios_notif = []
            summary_notif = None
            default_notice = ''
            if selected_meeting:
                m_socios = db.all('''
                    SELECT s.id, s.name, COALESCE(s.phone, '') AS phone, COALESCE(s.email, '') AS email,
                           (SELECT GROUP_CONCAT(u.code, ', ') FROM units u WHERE u.socio_id=s.id) AS unit_code,
                           mn.notified, mn.notified_at
                    FROM socios s
                    LEFT JOIN meeting_notifications mn ON mn.socio_id = s.id AND mn.meeting_id = ?
                    WHERE s.active = 1 OR mn.meeting_id IS NOT NULL
                    ORDER BY s.name ASC
                ''', (selected_meeting_id,))
                for s in m_socios:
                    if s['notified'] is not None:
                        is_n = bool(s['notified'])
                    else:
                        is_n = bool(selected_meeting['notice_sent_at'])
                    socios_notif.append({
                        'id': s['id'],
                        'name': s['name'],
                        'phone': s['phone'] or '—',
                        'email': s['email'] or '—',
                        'unit_code': s['unit_code'] or '—',
                        'notified': is_n,
                        'notified_at': s['notified_at']
                    })
                tot = len(socios_notif)
                notifs = sum(1 for s in socios_notif if s['notified'])
                summary_notif = {
                    'total': tot,
                    'notificados': notifs,
                    'pendientes': tot - notifs
                }
                if not selected_meeting['notice']:
                    default_notice = (
                        f"Se convoca a los señores socios a la reunión de {selected_meeting['type']} "
                        f"que se llevará a cabo el día {selected_meeting['meeting_date']} a las {selected_meeting['meeting_time']} "
                        f"en {selected_meeting['location']}.\n\n"
                        f"Orden del día:\n{selected_meeting['agenda'] or '1. Constatación del quórum.\n2. Tratamiento del orden del día.'}"
                    )

            extra.update(
                can_manage_convocatoria=has(request, 'actas.editar'),
                meetings=meetings,
                selected_meeting=selected_meeting,
                socios_notif=socios_notif,
                summary_notif=summary_notif,
                default_notice=default_notice
            )

        return render(request,'module.html',active=module_name,mod=module_name,tab=tab,
                      tabs=TABS[module_name],title=TITLES[module_name],subtitle=SUBTITLES[module_name],data=data,fmt=fmt,available_reports={k:v for k,v in REPORT_TYPES.items() if has(request,'reportes.'+k)},
                      can_edit=has(request,'roles.editar'),can_close=has(request,'cierres.ejecutar'),**extra)

    return app
