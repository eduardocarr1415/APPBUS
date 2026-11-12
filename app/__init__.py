"""BusGestión: FastAPI, SQLite and permissions. Run through run.py."""
import json
import os
import secrets
import re
import sqlite3
from datetime import date, timedelta
from html import escape
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import Database, PERMISSIONS
from .security import (password_hash,password_ok,password_valid,utcnow,nowstr,token_hash,make_session,
                       locked,register_failure,reset_failures,safe_text,valid_email,valid_username,
                       money,valid_date)
from .views import NAV,TABS,TITLES,SUBTITLES,modules
from .forms import PERM_CREATE, spec, save, field_errors_for
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
    if not testing:
        db.ensure_default_admin()
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
        user = current(request)
        curr_s = db.get_settings()
        nav_items = []
        for k, url, icon, label, p in NAV:
            if not p or has(request, p):
                dyn_icon = curr_s.get(f'icon_{k}', icon)
                dyn_title = curr_s.get(f'title_{k}', label)
                nav_items.append({'key': k, 'url': url, 'icon': dyn_icon, 'title': dyn_title})
        return {'request': request, 'user': user, 'csrf': getattr(request.state, 'csrf', ''),
                'nav': nav_items,
                'active': more.get('active', ''), 'ok': request.query_params.get('ok', '')[:160],
                'perms': getattr(request.state, 'perms', set()), 'year': date.today().year,
                'period': db.current_period(), 'settings': curr_s, **more}

    def render(request, template, status_code=200,**more):
        return TEMPLATES.TemplateResponse(request,template,context(request,**more),status_code=status_code)

    def redir(url,msg=None):
        sep = '&ok=' if '?' in url else '?ok='
        return RedirectResponse(url+(sep+quote(msg) if msg else ''),status_code=303)

    def parent(kind):
        return {'socios':'/socios','traspasos':'/socios?tab=traspasos','vehiculos':'/unidades?tab=vehiculos','unidades':'/unidades','cambios':'/unidades?tab=cambios',
                'reuniones':'/actas?tab=reuniones','actas':'/actas?tab=actas','convocatorias':'/actas?tab=convocatorias',
                'asistencia':'/actas?tab=asistencia','ingresos':'/finanzas?tab=ingresos','pagos':'/finanzas?tab=pagos',
                'deudas':'/finanzas?tab=deudas','multas':'/multas',
                'usuarios':'/usuarios'}.get(kind,'/')

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

    def render_weekly_mark_form(request,week_start,amount='',error=None,status_code=200):
        socios=db.all('SELECT id,name FROM socios WHERE active=1 ORDER BY name')
        period=db.current_period()
        existing=db.one('SELECT id FROM weekly_marks WHERE week_start=? LIMIT 1',(week_start,))
        can_create=(not period['closed_at'] and period['starts']<=week_start<=date.today().isoformat()
                    and not existing and bool(socios))
        return render(request,'weekly_mark_form.html',status_code=status_code,active='finanzas',
                      week_start=week_start,entries=socios,amount=amount,period=period,
                      can_create=can_create,today=date.today().isoformat(),
                      existing=bool(existing),error=error)

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
        try:
            username=valid_username(username)
            username_is_valid=True
        except ValueError:
            username_is_valid=False
            username=username[:32]
        ip=client_ip(request)
        with db.connection() as con:
            if locked(con,username,ip):
                Database.audit(con,None,'Bloqueo temporal','autenticacion',None,f"Acceso temporalmente bloqueado para '{username}' desde IP {ip} por 15 minutos", ip=ip)
                return render(request,'login.html',status_code=429,error='Demasiados intentos. Inténtelo nuevamente en 15 minutos.')
            if not username_is_valid or len(pwd)>128:
                register_failure(con,username,ip)
                Database.audit(con,None,'Intento fallido','autenticacion',None,f"Intento de acceso fallido con usuario inválido '{username}' desde IP {ip}", ip=ip)
                return render(request,'login.html',status_code=401,error='Usuario o contraseña incorrectos.')
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
        return redir('/login')

    @app.post('/recuperar')
    async def recover(request:Request):
        return redir('/login')

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

    @app.get('/marcaciones/nueva')
    def new_weekly_marks(request:Request,week_start:str=''):
        permitted(request,'finanzas.editar')
        selected=week_start or date.today().isoformat()
        try:
            selected=valid_date(selected).isoformat()
        except ValueError as exc:
            raise HTTPException(400,'Seleccione una fecha válida.') from exc
        return render_weekly_mark_form(request,selected)

    @app.post('/marcaciones/nueva')
    async def create_weekly_marks(request:Request):
        permitted(request,'finanzas.editar')
        form=await csrf_check(request)
        raw_date=str(form.get('week_start','')).strip()
        try:
            week_start=valid_date(raw_date).isoformat()
        except ValueError:
            week_start=date.today().isoformat()
            return render_weekly_mark_form(request,week_start,error='Seleccione una fecha válida.',
                                           status_code=400)
        socios=db.all('SELECT id,name FROM socios WHERE active=1 ORDER BY name')
        if not socios:
            raise HTTPException(400,'No hay socios activos para generar la marcación.')
        raw_amount=str(form.get('amount','')).strip()
        try:
            amount=money(raw_amount)
            if amount<=0:
                raise ValueError('El valor del aporte debe ser mayor que cero.')
        except ValueError as exc:
            return render_weekly_mark_form(request,week_start,raw_amount,str(exc),status_code=400)
        period=db.current_period()
        if period['closed_at']:
            return render_weekly_mark_form(request,week_start,raw_amount,
                'El periodo financiero está cerrado; no se pueden crear marcaciones.',status_code=400)
        if not period['starts']<=week_start<=date.today().isoformat():
            return render_weekly_mark_form(request,week_start,raw_amount,
                f'La fecha debe estar entre {period["starts"]} y hoy.',status_code=400)
        if db.one('SELECT id FROM weekly_marks WHERE week_start=? LIMIT 1',(week_start,)):
            return render_weekly_mark_form(request,week_start,raw_amount,
                'Ya existe una marcación para esta fecha. Consulte el historial para evitar duplicados.',
                status_code=400)

        uid=current(request)['id']
        try:
            with db.connection() as con:
                current_period=Database.ensure_period(con,date.today())
                if current_period['closed_at']:
                    raise HTTPException(400,'El periodo financiero está cerrado; no se pueden crear marcaciones.')
                for socio in socios:
                    con.execute('''INSERT INTO weekly_marks
                        (period_id,socio_id,week_start,concept,amount_cents,state,created_by)
                        VALUES(?,?,?,?,?,'Pendiente',?)''',
                        (current_period['id'],socio['id'],week_start,'Marcación semanal',
                         amount,uid))
                Database.audit(con,uid,'Crear marcación semanal','weekly_marks',None,
                               f"{week_start}: {len(socios)} socios registrados.")
        except sqlite3.IntegrityError as exc:
            return render_weekly_mark_form(request,week_start,raw_amount,
                'Ya existe una marcación para esta fecha o uno de sus valores no es válido.',
                status_code=400)
        return redir(f'/finanzas?tab=marcaciones&desde={week_start}&hasta={week_start}',
                     'Marcación semanal generada para todos los socios activos.')

    @app.post('/marcaciones/{mark_id}/pagar')
    async def pay_weekly_mark(request:Request,mark_id:int):
        permitted(request,'finanzas.editar')
        form=await csrf_check(request)
        try:
            amount=money(form.get('amount',''))
        except ValueError as exc:
            raise HTTPException(400,str(exc)) from exc
        if amount<=0:
            raise HTTPException(400,'El valor del abono debe ser mayor que cero.')
        method='Efectivo'
        uid=current(request)['id']
        today=date.today().isoformat()
        with db.connection() as con:
            try:
                period=active_period_for_write(con)
            except ValueError as exc:
                raise HTTPException(400,str(exc)) from exc
            mark=con.execute('''SELECT w.*,s.name AS socio_name FROM weekly_marks w
                JOIN socios s ON s.id=w.socio_id WHERE w.id=?''',(mark_id,)).fetchone()
            if not mark:
                raise HTTPException(404,'Marcación semanal no encontrada.')
            if mark['state']!='Pendiente':
                raise HTTPException(400,'Esta marcación ya fue pagada.')
            if mark['amount_cents']<=0:
                raise HTTPException(400,'El valor de la marcación debe ser mayor que cero antes de cobrar.')
            remaining=mark['amount_cents']-mark['paid_cents']
            if amount>remaining:
                raise HTTPException(400,'El abono no puede ser mayor que el saldo pendiente.')
            total_paid=mark['paid_cents']+amount
            state='Pagado' if total_paid==mark['amount_cents'] else 'Pendiente'
            income_id=con.execute('''INSERT INTO incomes
                (period_id,socio_id,category,concept,amount_cents,method,day,created_by)
                VALUES(?,?,?,?,?,?,?,?)''',
                (period['id'],mark['socio_id'],'Marcación semanal',
                 f"Marcación semanal · {mark['week_start']}",amount,method,today,uid)).lastrowid
            updated=con.execute('''UPDATE weekly_marks SET state=?,paid_cents=?,paid_at=CURRENT_TIMESTAMP,
                payment_method=?,income_id=? WHERE id=? AND state='Pendiente' AND paid_cents=?''',
                (state,total_paid,method,income_id,mark_id,mark['paid_cents'])).rowcount
            if updated!=1:
                raise HTTPException(409,'La marcación cambió mientras se registraba el pago. Recargue la lista.')
            Database.audit(con,uid,'Pagar marcación semanal','weekly_marks',mark_id,
                f"{mark['socio_name']}: abono de {amount/100:.2f} S/; acumulado "
                f"{total_paid/100:.2f} S/ de {mark['amount_cents']/100:.2f} S/ ({method})")
        return redir(f'/finanzas?tab=marcaciones&desde={mark["week_start"]}&hasta={mark["week_start"]}&lista=1',
                     'Abono registrado en Finanzas; la marcación sigue pendiente.' if state=='Pendiente'
                     else 'Aporte completado; la marcación figura como pagada.')

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
        return render(request,'form.html',active='',form=s,values=initial,error=None,errors={},cancel=parent(kind),editing=False,
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
            return render(request,'form.html',status_code=400,active='',form=spec(db,kind),values=values,
                          error=msg,errors=field_errors_for(exc),cancel=parent(kind),editing=False,
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
        return render(request,'form.html',active='',form=spec(db,kind),values={f:str(item[column] or '') for f,column in EDIT_KEYS[kind].items()},error=None,errors={},cancel=parent(kind),editing=True,record_id=record_id,
                      socio_lookup=socios_l,unit_lookup=units_l,socio_lookup_json=json.dumps(socios_l),unit_lookup_json=json.dumps(units_l))

    @app.post('/editar/{kind}/{record_id}')
    async def edit_save(request:Request,kind:str,record_id:int):
        permitted(request,EDITABLE.get(kind,('', '__no__'))[1])
        f=await csrf_check(request)
        v={k:str(val) for k,val in f.items() if k!='_csrf'}
        try:save(db,kind,v,current(request)['id'],record_id,ip=client_ip(request))
        except (ValueError,sqlite3.IntegrityError) as exc:
            msg='No se pudo guardar: ya existe un registro igual o faltan datos válidos.' if isinstance(exc,sqlite3.IntegrityError) else str(exc)
            socios_l, units_l = get_socio_unit_data()
            return render(request,'form.html',active='',form=spec(db,kind),values=v,error=msg,
                          errors=field_errors_for(exc),cancel=parent(kind),editing=True,record_id=record_id,status_code=400,
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

    @app.get('/multas/{fine_id}/pagar')
    def pay_fine_page(request:Request,fine_id:int):
        if not (has(request,'multas.editar') or has(request,'finanzas.editar')):
            raise HTTPException(403,'No tiene permisos para cobrar multas.')
        fine=db.one('SELECT f.*,s.name AS socio_name,s.cedula AS socio_cedula,u.code AS unit_code FROM fines f JOIN socios s ON s.id=f.socio_id LEFT JOIN units u ON u.id=f.unit_id WHERE f.id=?',(fine_id,))
        if not fine: raise HTTPException(404,'Multa no encontrada.')
        if fine['status']!='Pendiente':
            return redir('/multas',f'La multa #{fine_id} ya se encuentra en estado {fine["status"]}.')
        debt=db.one('SELECT * FROM debts WHERE fine_id=?',(fine_id,))
        pending=(debt['amount_cents']-debt['paid_cents']) if debt else fine['amount_cents']
        return render(request,'pay_fine.html',active='multas',fine=fine,
                      amount_fmt=fmt(pending),today=date.today().isoformat())

    @app.post('/multas/{fine_id}/pagar')
    async def pay_fine_action(request:Request,fine_id:int):
        if not (has(request,'multas.editar') or has(request,'finanzas.editar')):
            raise HTTPException(403,'No tiene permisos para cobrar multas.')
        f=await csrf_check(request)
        method=str(f.get('method','Efectivo')).strip()
        if method not in ('Efectivo','Transferencia','Depósito'):
            method='Efectivo'
        pay_day=str(f.get('day',date.today().isoformat())).strip() or date.today().isoformat()
        notes=str(f.get('notes','')).strip()
        ip=client_ip(request)
        uid=current(request)['id']
        with db.connection() as con:
            period=active_period_for_write(con)
            fine=con.execute('SELECT * FROM fines WHERE id=?',(fine_id,)).fetchone()
            if not fine or fine['status']!='Pendiente':
                raise HTTPException(400,'Solo se pueden cobrar multas en estado Pendiente.')
            debt=con.execute('SELECT * FROM debts WHERE fine_id=?',(fine_id,)).fetchone()
            if not debt:
                debt_id=con.execute(
                    'INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued,fine_id,created_by) VALUES(?,?,?,?,?,?,?)',
                    (fine['period_id'],fine['socio_id'],'Multa: '+fine['reason'],fine['amount_cents'],fine['occurred_at'],fine_id,uid)
                ).lastrowid
                debt=con.execute('SELECT * FROM debts WHERE id=?',(debt_id,)).fetchone()

            pending=debt['amount_cents']-debt['paid_cents']
            if pending<=0:
                con.execute("UPDATE fines SET status='Pagada' WHERE id=?",(fine_id,))
                return redir('/multas?tab=pagadas',f'La multa #{fine_id} ya se encontraba saldada.')

            pay_id=con.execute(
                'INSERT INTO payments(period_id,debt_id,socio_id,amount_cents,method,day,created_by) VALUES(?,?,?,?,?,?,?)',
                (period['id'],debt['id'],debt['socio_id'],pending,method,pay_day,uid)
            ).lastrowid
            con.execute('UPDATE debts SET paid_cents=paid_cents+? WHERE id=?',(pending,debt['id']))
            con.execute("UPDATE fines SET status='Pagada' WHERE id=?",(fine_id,))
            note_str=f" ({notes})" if notes else ""
            Database.audit(con,uid,'Pagar multa','multas',fine_id,
                           f"Cobro y pago de Multa #{fine_id} por {pending/100:.2f} S/ ({method}){note_str}", ip=ip)
            Database.audit(con,uid,'Registrar','pagos',pay_id,
                           f"Abono de {pending/100:.2f} S/ a deuda #{debt['id']} por multa #{fine_id} ({method}){note_str}", ip=ip)
        return redir('/multas?tab=pagadas',f'Multa #{fine_id} pagada y registrada exitosamente.')

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
    def download_report(request:Request,kind:str,format:str,period_id:int=0,
                        fine_cycle_id:int=0,month:str=''):
        permitted(request,'reportes.ver')
        if kind=='gerencia':
            permitted(request,'reportes.general')
        elif kind in REPORT_TYPES:
            permitted(request,'reportes.'+kind)
        if kind not in REPORT_TYPES or format not in ('pdf','csv'):raise HTTPException(404,'Tipo de reporte no disponible.')
        if kind=='multas':
            cycle=db.one('SELECT * FROM fine_cycles WHERE id=?',(fine_cycle_id,)) if fine_cycle_id else db.current_fine_cycle()
            if not cycle:raise HTTPException(404,'Ciclo de multas no encontrado.')
            period={'id':cycle['id'],'label':cycle['label'],'starts':cycle['starts'],
                    'ends':cycle['ends'] or date.today().isoformat()}
            heads,rows=build_rows(db,kind,0,fine_cycle_id=cycle['id'])
            filename=f'reporte_multas_{cycle["label"]}.{format}'
        elif kind=='gerencia':
            try:
                month_date=date.fromisoformat(month+'-01')
            except ValueError as exc:
                raise HTTPException(400,'Seleccione un mes válido.') from exc
            if month_date.strftime('%Y-%m')!=month:
                raise HTTPException(400,'Seleccione un mes válido.')
            next_month=(month_date.replace(day=28)+timedelta(days=4)).replace(day=1)
            period={'starts':month_date.isoformat(),
                    'ends':(next_month-timedelta(days=1)).isoformat()}
            heads,rows=build_rows(db,kind,0,month=month)
            filename=f'informe_gerencial_{month}.{format}'
        else:
            period=db.one('SELECT * FROM periods WHERE id=?',(period_id,)) if period_id else db.current_period()
            if not period:raise HTTPException(404,'Periodo no encontrado.')
            heads,rows=build_rows(db,kind,period['id'])
            filename=f'reporte_{kind}_{period["label"]}.{format}'
        blob=as_pdf(REPORT_TYPES[kind],period,heads,rows) if format=='pdf' else as_csv(heads,rows)
        med='application/pdf' if format=='pdf' else 'text/csv; charset=utf-8'
        return Response(blob,media_type=med,headers={'Content-Disposition':f'attachment; filename="{filename}"'})

    @app.post('/cierre')
    async def close_year(request:Request):
        permitted(request,'cierres.ejecutar')
        f=await csrf_check(request)
        cycle=db.current_fine_cycle()
        try:
            close_date=date.fromisoformat(str(f.get('close_date','')).strip())
        except ValueError as exc:
            raise HTTPException(400,'Seleccione una fecha de cierre válida.') from exc
        if not date.fromisoformat(cycle['starts'])<=close_date<=date.today():
            raise HTTPException(400,'La fecha de cierre debe estar entre el inicio del ciclo y hoy.')
        expected='CERRAR '+cycle['label']
        if str(f.get('confirmacion','')).strip()!=expected:
            raise HTTPException(400,f'Para confirmar escriba exactamente: {expected}')
        with db.connection() as con:
            current_cycle=con.execute('SELECT * FROM fine_cycles WHERE id=? AND closed_at IS NULL',(cycle['id'],)).fetchone()
            if not current_cycle:raise HTTPException(400,'El ciclo de multas ya está cerrado.')
            latest=con.execute('SELECT MAX(occurred_at) AS latest FROM fines WHERE fine_cycle_id=?',(cycle['id'],)).fetchone()['latest']
            if latest and latest>close_date.isoformat():
                raise HTTPException(400,'Hay multas con fecha posterior al cierre seleccionado. Elija una fecha que las incluya.')
            totals=con.execute('''SELECT COUNT(*) AS count,COALESCE(SUM(amount_cents),0) AS total,
                COALESCE(SUM(CASE WHEN status='Pendiente' THEN amount_cents ELSE 0 END),0) AS pending,
                COALESCE(SUM(CASE WHEN status='Pagada' THEN amount_cents ELSE 0 END),0) AS paid
                FROM fines WHERE fine_cycle_id=?''',(cycle['id'],)).fetchone()
            snapshot=json.dumps(dict(totals),ensure_ascii=False)
            con.execute('UPDATE fine_cycles SET ends=?,closed_at=CURRENT_TIMESTAMP,closed_by=?,snapshot=? WHERE id=?',
                        (close_date.isoformat(),current(request)['id'],snapshot,cycle['id']))
            Database.ensure_fine_cycle(con,close_date+timedelta(days=1))
            Database.audit(con,current(request)['id'],'Cerrar ciclo de multas','ciclos_multas',cycle['id'],
                           f"Ciclo {cycle['label']} cerrado al {close_date.isoformat()}; {totals['count']} multas.")
        return redir('/reportes?tab=cierre','Ciclo de multas cerrado. El historial y sus totales se conservaron.')

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

        try:
            notice = safe_text(f.get('notice', ''),'Texto de la convocatoria',5000)
        except ValueError as exc:
            raise HTTPException(400,str(exc)) from exc
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

    async def save_uploaded_branding_file(file_obj, prefix: str) -> str | None:
        if file_obj and hasattr(file_obj, 'filename') and file_obj.filename:
            fname = file_obj.filename.strip()
            ext = Path(fname).suffix.lower()
            if ext not in ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.ico'):
                raise HTTPException(400, f'Formato no permitido para {prefix}. Solo se admiten PNG, JPG, JPEG, SVG, WEBP o ICO.')
            content = await file_obj.read()
            if len(content) > 4 * 1024 * 1024:
                raise HTTPException(400, f'El archivo de imagen {prefix} no puede superar 4 MB.')
            branding_dir = app.state.upload_dir / 'branding'
            branding_dir.mkdir(parents=True, exist_ok=True)
            safe_name = f"{prefix}_{secrets.token_hex(4)}{ext}"
            dest = branding_dir / safe_name
            dest.write_bytes(content)
            return f"/branding/{safe_name}"
        return None

    @app.get('/branding/{filename}')
    def get_branding_asset(filename: str):
        safe = re.sub(r'[^a-zA-Z0-9_\-\.]', '', filename)
        target = (app.state.upload_dir / 'branding' / safe).resolve()
        base_dir = (app.state.upload_dir / 'branding').resolve()
        if not str(target).startswith(str(base_dir)) or not target.exists():
            raise HTTPException(404, 'Imagen no encontrada')
        media = 'image/svg+xml' if safe.endswith('.svg') else ('image/png' if safe.endswith('.png') else ('image/x-icon' if safe.endswith('.ico') else 'image/jpeg'))
        return FileResponse(target, media_type=media)

    @app.get('/configuracion')
    def configuracion_page(request:Request):
        permitted(request, 'configuracion.ver')
        if current(request)['role'] != 'Administrador':
            raise HTTPException(403, 'Apartado reservado exclusivamente para el Administrador.')
        curr_settings = db.get_settings()
        return render(request, 'configuracion.html', active='configuracion',
                      current_settings=curr_settings)

    @app.post('/configuracion')
    async def configuracion_save(request:Request):
        permitted(request, 'configuracion.ver')
        if current(request)['role'] != 'Administrador':
            raise HTTPException(403, 'Apartado reservado exclusivamente para el Administrador.')
        f = await csrf_check(request)
        curr_s = db.get_settings()

        # Procesar posibles subidas de archivos
        up_logo = await save_uploaded_branding_file(f.get('header_logo_file'), 'logo')
        up_banner = await save_uploaded_branding_file(f.get('sidebar_banner_file'), 'banner')
        up_login = await save_uploaded_branding_file(f.get('login_banner_file'), 'login')
        up_fav = await save_uploaded_branding_file(f.get('favicon_file'), 'favicon')

        new_s = {
            # Identidad y textos
            'company_name': str(f.get('company_name', '')).strip()[:100] or curr_s.get('company_name', 'Compañía de Transportes Guaytacama'),
            'company_slogan': str(f.get('company_slogan', '')).strip()[:150] or curr_s.get('company_slogan', 'Buses Guaytacama · Servicio Interparroquial e Interprovincial'),
            'footer_text': str(f.get('footer_text', '')).strip()[:150] or curr_s.get('footer_text', 'Transportes Guaytacama · Sistema de Control Operativo y Flota'),
            'login_title': str(f.get('login_title', '')).strip()[:120] or curr_s.get('login_title', 'Sistema de Gestión de Compañía de Buses'),
            'login_subtitle': str(f.get('login_subtitle', '')).strip()[:180] or curr_s.get('login_subtitle', 'Accede a la plataforma de gestión de la compañía.'),

            # Logos e imágenes
            'header_logo_url': up_logo or str(f.get('header_logo_url', '')).strip()[:250] or curr_s.get('header_logo_url', '/static/bus-icon.svg'),
            'sidebar_banner_url': up_banner or str(f.get('sidebar_banner_url', '')).strip()[:250] or curr_s.get('sidebar_banner_url', '/static/bus-guaytacama.svg'),
            'login_banner_url': up_login or str(f.get('login_banner_url', '')).strip()[:250] or curr_s.get('login_banner_url', '/static/bus-landscape.svg'),
            'favicon_url': up_fav or str(f.get('favicon_url', '')).strip()[:250] or curr_s.get('favicon_url', '/static/favicon.svg'),

            # Colores y diseño
            'primary_color': str(f.get('primary_color', '#1d4ed8')).strip()[:20],
            'sidebar_color': str(f.get('sidebar_color', '#0f172a')).strip()[:20],
            'accent_color': str(f.get('accent_color', '#f59e0b')).strip()[:20],
            'page_bg_color': str(f.get('page_bg_color', '#f8fafc')).strip()[:20],
            'card_bg_color': str(f.get('card_bg_color', '#ffffff')).strip()[:20],
            'sidebar_text_color': str(f.get('sidebar_text_color', '#e2e8f0')).strip()[:20],
            'border_radius': str(f.get('border_radius', '14px')).strip()[:10],

            # Tipografía
            'font_family': str(f.get('font_family', 'Inter, system-ui, sans-serif')).strip()[:80],
            'font_size': str(f.get('font_size', '14px')).strip()[:10],

            # Pestañas
            'tabs_style': str(f.get('tabs_style', 'capsule')).strip()[:20],

            # Animación de bus
            'bus_animation': '1' if f.get('bus_animation') else '0',
            'animation_duration': str(f.get('animation_duration', '1.8')).strip()[:10],
            'bus_led_text': str(f.get('bus_led_text', 'GUAYTACAMA')).strip()[:30] or 'GUAYTACAMA',
            'bus_badge_tag': str(f.get('bus_badge_tag', 'RUTA GUAYTACAMA')).strip()[:40] or 'RUTA GUAYTACAMA',
            'bus_badge_sub': str(f.get('bus_badge_sub', '')).strip()[:120] or curr_s.get('bus_badge_sub', 'Buses Guaytacama · Puntualidad, Confort y Seguridad'),
        }

        # Iconos y títulos de módulos
        for mod_key in ('dashboard', 'socios', 'actas', 'finanzas', 'multas', 'unidades', 'reportes', 'usuarios', 'auditoria', 'configuracion'):
            icon_val = str(f.get(f'icon_{mod_key}', '')).strip()[:10]
            if icon_val:
                new_s[f'icon_{mod_key}'] = icon_val
            title_val = str(f.get(f'title_{mod_key}', '')).strip()[:50]
            if title_val:
                new_s[f'title_{mod_key}'] = title_val

        db.update_settings(new_s)
        ip = client_ip(request)
        with db.connection() as con:
            Database.audit(con, current(request)['id'], 'Configurar sistema', 'sistema', None,
                           f"Personalización visual y de empresa actualizada (Color: {new_s['primary_color']}, Animación: {new_s['bus_animation']})", ip=ip)
        return redir('/configuracion', 'Configuración de página guardada y aplicada correctamente.')

    @app.post('/configuracion/reset')
    async def configuracion_reset(request:Request):
        permitted(request, 'configuracion.ver')
        if current(request)['role'] != 'Administrador':
            raise HTTPException(403, 'Apartado reservado exclusivamente para el Administrador.')
        await csrf_check(request)
        db.reset_settings()
        ip = client_ip(request)
        with db.connection() as con:
            Database.audit(con, current(request)['id'], 'Restablecer configuración', 'sistema', None,
                           "Se restauraron los colores y textos predeterminados de fábrica", ip=ip)
        return redir('/configuracion', 'Se han restaurado los valores predeterminados de fábrica.')

    @app.get('/{module_name}')
    def module_page(request:Request,module_name:str,tab:str=''):
        # Keep this generic module route last among GET routes to avoid collisions.
        if module_name not in TABS: raise HTTPException(404,'Módulo no encontrado.')
        perm={'socios':'socios.ver','actas':'actas.ver','finanzas':'finanzas.ver','multas':'multas.ver',
              'unidades':'unidades.ver','vigilancia':'vigilancia.ver','reportes':'reportes.ver','usuarios':'usuarios.ver','auditoria':'auditoria.ver'}.get(module_name)
        permitted(request,perm)
        if module_name=='auditoria' and current(request)['role']!='Administrador':
            raise HTTPException(403,'Apartado reservado exclusivamente para el Administrador.')
        if not tab or tab not in dict(TABS[module_name]): tab=TABS[module_name][0][0]
        u=current(request)
        weekly_from=request.query_params.get('desde','').strip() if module_name=='finanzas' and tab=='marcaciones' else ''
        weekly_to=request.query_params.get('hasta','').strip() if module_name=='finanzas' and tab=='marcaciones' else ''
        weekly_state=request.query_params.get('estado','').strip() if module_name=='finanzas' and tab=='marcaciones' else ''
        weekly_list=(module_name=='finanzas' and tab=='marcaciones'
                     and request.query_params.get('lista')=='1')
        try:
            weekly_from=valid_date(weekly_from).isoformat() if weekly_from else ''
            weekly_to=valid_date(weekly_to).isoformat() if weekly_to else ''
        except ValueError as exc:
            raise HTTPException(400,'El filtro de fechas de marcación no es válido.') from exc
        if weekly_from and weekly_to and weekly_from>weekly_to:
            raise HTTPException(400,'La fecha inicial no puede ser posterior a la fecha final.')
        if weekly_state not in ('','Pagado','Pendiente'):
            raise HTTPException(400,'El estado de marcación no es válido.')
        data=modules(db,module_name,tab,u['role'],u['socio_id'],weekly_from,weekly_to,weekly_list,weekly_state)
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

        available_reports={k:v for k,v in REPORT_TYPES.items()
                           if has(request,'reportes.general' if k=='gerencia' else 'reportes.'+k)}
        return render(request,'module.html',active=module_name,mod=module_name,tab=tab,
                      tabs=TABS[module_name],title=TITLES[module_name],subtitle=SUBTITLES[module_name],data=data,fmt=fmt,available_reports=available_reports,
                      can_edit=has(request,'roles.editar'),can_close=has(request,'cierres.ejecutar'),**extra)

    return app
