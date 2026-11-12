"""Security and data-integrity regression tests. Run: python -m pytest -q"""
import re
import json
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app import create_app
from app.security import password_hash, money
from app.db import Database

@pytest.fixture
def environment(tmp_path):
    a=create_app(tmp_path/'demo.sqlite3',testing=True)
    db=a.state.db
    with db.connection() as con:
        admin=con.execute("SELECT id FROM roles WHERE name='Administrador'").fetchone()['id']
        vigilancia=con.execute("SELECT id FROM roles WHERE name='Vigilancia'").fetchone()['id']
        socio_role=con.execute("SELECT id FROM roles WHERE name='Socio'").fetchone()['id']
        sid=con.execute('INSERT INTO socios(name,joined) VALUES(?,?)',('Socio Uno',date.today().isoformat())).lastrowid
        other=con.execute('INSERT INTO socios(name,joined) VALUES(?,?)',('Socio Dos',date.today().isoformat())).lastrowid
        aid=con.execute('INSERT INTO users(username,full_name,password_hash,role_id) VALUES(?,?,?,?)',('admin','Admin Prueba',password_hash('SecurePass123456'),admin)).lastrowid
        vid=con.execute('INSERT INTO users(username,full_name,password_hash,role_id) VALUES(?,?,?,?)',('vigilante','Control Prueba',password_hash('SecurePass123456'),vigilancia)).lastrowid
        sid_user=con.execute('INSERT INTO users(username,full_name,password_hash,role_id,socio_id) VALUES(?,?,?,?,?)',('socio','Socio Uno',password_hash('SecurePass123456'),socio_role,sid)).lastrowid
    with TestClient(a,raise_server_exceptions=True) as c:
        yield a,db,c,sid,other,aid,vid,sid_user

def csrf(client,url='/login'):
    response=client.get(url)
    assert response.status_code==200,response.text[:300]
    return re.search(r'name="_csrf" value="([^"]+)"',response.text).group(1)

def login(client,name='admin'):
    token=csrf(client)
    resp=client.post('/login',data={'username':name,'password':'SecurePass123456','_csrf':token},follow_redirects=True)
    assert resp.status_code==200
    assert '<h1>Dashboard' in resp.text

def post(client,path,form={},follow_redirects=False):
    # /perfil contains a hidden CSRF after authenticated login.
    token=csrf(client,'/perfil')
    return client.post(path,data={'_csrf':token,**form},follow_redirects=follow_redirects)

def test_protected_routes_and_login(environment):
    app,db,c,*_=environment
    assert c.get('/usuarios',follow_redirects=False).status_code==303
    page=c.get('/login')
    assert 'Iniciar sesión' in page.text
    assert 'data-password-toggle="login-password"' in page.text
    assert 'id="login-password" type="password"' in page.text
    assert 'data-password-icon="show"' in page.text and 'data-password-icon="hide"' in page.text
    assert 'aria-label="Mostrar contraseña" aria-pressed="false"' in page.text
    assert '>Mostrar</button>' not in page.text
    token=csrf(c)
    res=c.post('/login',data={'_csrf':token,'username':'admin','password':'incorrect'},follow_redirects=False)
    assert res.status_code==401
    login(c)
    assert c.get('/usuarios').status_code==200
    assert c.get('/usuarios?tab=permisos').status_code==200
    assert c.get('/reportes?tab=cierre').status_code==200

def test_csrf_and_access_control(environment):
    app,db,c,sid,other,*_=environment
    login(c,'vigilante')
    assert c.get('/nuevo/usuarios').status_code==403
    assert c.get('/reportes').status_code==200
    assert c.get('/reporte/deudas.pdf').status_code==403
    assert c.get('/reporte/multas.pdf').status_code==200
    assert c.post('/nuevo/multas',data={'socio_id':str(sid)}).status_code==403
    assert c.get('/usuarios').status_code==403

def test_fines_create_debt_then_payment(environment):
    app,db,c,sid,other,*_=environment
    login(c)
    today=date.today().isoformat()
    fine=post(c,'/nuevo/multas',{'socio_id':str(sid),'unit_id':'','category':'Atraso','reason':'Atraso en salida',
                                    'occurred_at':today,'amount':'50.50'})
    assert fine.status_code==303
    f=db.one('SELECT * FROM fines ORDER BY id DESC LIMIT 1')
    assert f['amount_cents']==5050
    debt=db.one('SELECT * FROM debts WHERE fine_id=?',(f['id'],))
    assert debt['amount_cents']==5050 and debt['paid_cents']==0
    bad=post(c,'/nuevo/pagos',{'debt_id':str(debt['id']),'amount':'100','day':today,'method':'Efectivo'})
    assert bad.status_code==400
    good=post(c,'/nuevo/pagos',{'debt_id':str(debt['id']),'amount':'50.50','day':today,'method':'Efectivo'})
    assert good.status_code==303
    assert db.one('SELECT paid_cents FROM debts WHERE id=?',(debt['id'],))['paid_cents']==5050
    assert db.one('SELECT status FROM fines WHERE id=?',(f['id'],))['status']=='Pagada'
    assert db.one('SELECT COUNT(*) n FROM audit WHERE entity=?',('pagos',))['n']==1

def test_socio_only_sees_own_finances(environment):
    app,db,c,sid,other,*_=environment
    today=date.today().isoformat()
    period=db.current_period()
    with db.connection() as con:
        con.execute('INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued) VALUES(?,?,?,?,?)',(period['id'],sid,'Deuda propia',10000,today))
        con.execute('INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued) VALUES(?,?,?,?,?)',(period['id'],other,'Deuda privada de otro socio',90000,today))
        con.execute('INSERT INTO units(code,socio_id) VALUES(?,?)',('U-001',sid))
        con.execute('INSERT INTO units(code,socio_id) VALUES(?,?)',('U-999',other))
    login(c,'socio')
    r=c.get('/finanzas?tab=deudas')
    assert r.status_code==200 and 'Deuda propia' in r.text
    assert 'Deuda privada de otro socio' not in r.text
    assert c.get('/finanzas?tab=egresos').status_code==403
    assert c.get('/nuevo/egresos').status_code==403
    r=c.get('/unidades')
    assert 'U-001' in r.text and 'U-999' not in r.text
    assert c.get('/nuevo/deudas').status_code==403
    assert c.get('/reportes').status_code==403

def test_report_outputs_and_period_close_guard(environment):
    app,db,c,sid,*_=environment
    login(c)
    today=date.today().isoformat()
    income=post(c,'/nuevo/ingresos',{'day':today,'socio_id':'','category':'Otros',
        'concept':'Aporte de prueba','amount':'100.00','method':'Transferencia'})
    assert income.status_code==303
    expense=post(c,'/nuevo/egresos',{'day':today,'category':'Mantenimiento',
        'concept':'Reparación','recipient':'Proveedor Uno','amount':'25.00','method':'Efectivo'})
    assert expense.status_code==303
    expenses_page=c.get('/finanzas?tab=egresos')
    assert expenses_page.status_code==200 and 'Proveedor Uno' in expenses_page.text
    assert 'Pagos' not in expenses_page.text
    assert db.one("SELECT COUNT(*) n FROM audit WHERE entity='egresos'")['n']==1
    financial_csv=c.get('/reporte/finanzas.csv')
    assert financial_csv.status_code==200 and b'Proveedor Uno' in financial_csv.content

    pdf=c.get('/reporte/general.pdf')
    assert pdf.status_code==200 and pdf.content.startswith(b'%PDF-')
    csv=c.get('/reporte/deudas.csv')
    assert csv.status_code==200 and csv.content.startswith(b'\xef\xbb\xbf')
    month=date.today().strftime('%Y-%m')
    prior_month=(date.today().replace(day=1)-timedelta(days=1)).strftime('%Y-%m')
    with db.connection() as con:
        period_id=db.current_period()['id']
        con.execute('INSERT INTO incomes(period_id,concept,category,amount_cents,method,day) VALUES(?,?,?,?,?,?)',
                    (period_id,'Saldo inicial','Otros',5000,'Efectivo',prior_month+'-15'))
        con.execute('INSERT INTO expenses(period_id,category,concept,amount_cents,method,day) VALUES(?,?,?,?,?,?)',
                    (period_id,'Otros','Egreso anterior',1000,'Efectivo',prior_month+'-20'))
    monthly_financial=c.get('/reporte/finanzas.csv?month='+month)
    assert monthly_financial.status_code==200
    assert b'Aporte de prueba' in monthly_financial.content and b'Reparaci' in monthly_financial.content
    assert b'Saldo inicial' not in monthly_financial.content and b'Egreso anterior' not in monthly_financial.content
    monthly_financial_pdf=c.get('/reporte/finanzas.pdf?month='+month)
    assert monthly_financial_pdf.status_code==200 and monthly_financial_pdf.content.startswith(b'%PDF-')
    assert 'reporte_finanzas_'+month+'.pdf' in monthly_financial_pdf.headers['content-disposition']
    monthly=c.get('/reporte/gerencia.csv?month='+month)
    assert monthly.status_code==200 and b'Ingresos registrados' in monthly.content
    assert b'Total de ingresos' in monthly.content and b'S/ 100.00' in monthly.content
    assert b'Total de egresos' in monthly.content and b'S/ 25.00' in monthly.content
    assert b'Saldo disponible al inicio del mes' in monthly.content and b'S/ 40.00' in monthly.content
    assert b'Balance neto del mes' in monthly.content and b'S/ 75.00' in monthly.content
    assert b'Saldo disponible al cierre del mes' in monthly.content and b'S/ 115.00' in monthly.content
    monthly_pdf=c.get('/reporte/gerencia.pdf?month='+month)
    assert monthly_pdf.status_code==200 and monthly_pdf.content.startswith(b'%PDF-')
    assert c.get('/reportes?tab=resumen').status_code==200
    finances_page=c.get('/reportes?tab=financieros')
    assert finances_page.status_code==200 and 'Balance económico mensual' in finances_page.text
    assert finances_page.text.count('Ingresos y egresos')==1

    assert 'Reportes disponibles' not in finances_page.text
    assert c.get('/reportes?tab=cierre').status_code==200
    assert c.get('/vigilancia').status_code==404

    cycle=db.current_fine_cycle()
    fine=post(c,'/nuevo/multas',{'socio_id':str(sid),'unit_id':'','category':'Atraso',
        'reason':'Prueba de cierre','occurred_at':date.today().isoformat(),'amount':'25'})
    assert fine.status_code==303
    fine_record=db.one('SELECT * FROM fines ORDER BY id DESC LIMIT 1')
    assert fine_record['fine_cycle_id']==cycle['id']

    period=db.current_period()
    invalid_close=post(c,'/cierre',{'close_date':date.today().isoformat(),
        'confirmacion':'incorrecto'})
    assert invalid_close.status_code==400
    assert db.one('SELECT closed_at FROM fine_cycles WHERE id=?',(cycle['id'],))['closed_at'] is None
    closed=post(c,'/cierre',{'close_date':date.today().isoformat(),
        'confirmacion':'CERRAR '+cycle['label']})
    assert closed.status_code==303
    old_cycle=db.one('SELECT * FROM fine_cycles WHERE id=?',(cycle['id'],))
    assert old_cycle['ends']==date.today().isoformat() and old_cycle['closed_at']
    assert json.loads(old_cycle['snapshot'])['count']==1
    next_cycle=db.current_fine_cycle()
    assert next_cycle['starts']==(date.today()+timedelta(days=1)).isoformat()
    assert db.one('SELECT closed_at FROM periods WHERE id=?',(period['id'],))['closed_at'] is None
    assert db.one('SELECT fine_cycle_id FROM fines WHERE id=?',(fine_record['id'],))['fine_cycle_id']==cycle['id']
    income_after_close=post(c,'/nuevo/ingresos',{'day':date.today().isoformat(),
        'socio_id':'','category':'Otros','concept':'Ingreso luego del cierre',
        'amount':'5','method':'Efectivo'})
    assert income_after_close.status_code==303
    old_report=c.get(f'/reporte/multas.csv?fine_cycle_id={cycle["id"]}')
    assert old_report.status_code==200 and b'Prueba de cierre' in old_report.content
    current_report=c.get(f'/reporte/multas.csv?fine_cycle_id={next_cycle["id"]}')
    assert current_report.status_code==200 and b'Prueba de cierre' not in current_report.content


def test_legacy_fines_are_migrated_to_cycles_idempotently(tmp_path):
    path=tmp_path/'legacy.sqlite3'
    today=date.today()
    ending=today.year if today<=date(today.year,12,25) else today.year+1
    starts=f'{ending-1}-12-26'
    ends=f'{ending}-12-25'
    con=sqlite3.connect(path)
    con.executescript('''
        CREATE TABLE periods(id INTEGER PRIMARY KEY,label TEXT UNIQUE,starts TEXT,ends TEXT,
            closed_at TEXT,closed_by INTEGER,snapshot TEXT);
        CREATE TABLE socios(id INTEGER PRIMARY KEY,name TEXT);
        CREATE TABLE fines(id INTEGER PRIMARY KEY,period_id INTEGER,socio_id INTEGER,unit_id INTEGER,
            category TEXT,reason TEXT,occurred_at TEXT,amount_cents INTEGER,status TEXT,
            created_by INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    ''')
    con.execute('INSERT INTO periods(id,label,starts,ends) VALUES(1,?,?,?)',
                (str(ending),starts,ends))
    con.execute('INSERT INTO socios(id,name) VALUES(1,?)',('Socio legado',))
    con.execute('''INSERT INTO fines(id,period_id,socio_id,category,reason,occurred_at,amount_cents,status)
        VALUES(1,1,1,'Atraso','Multa legado',?,5000,'Pendiente')''',(today.isoformat(),))
    con.commit()
    con.close()

    db=Database(path)
    db.init()
    first=db.one('SELECT fine_cycle_id FROM fines WHERE id=1')['fine_cycle_id']
    cycle=db.one('SELECT * FROM fine_cycles WHERE id=?',(first,))
    assert cycle['source_period_id']==1 and cycle['starts']==starts and cycle['ends'] is None
    assert db.one('SELECT snapshot FROM fine_cycles WHERE id=?',(first,))['snapshot'] is not None
    db.init()
    assert db.one('SELECT COUNT(*) AS n FROM fine_cycles')['n']==1
    assert db.one('SELECT fine_cycle_id FROM fines WHERE id=1')['fine_cycle_id']==first


def test_permissions_survive_reinitialization(environment):
    app,db,c,*_=environment
    login(c)
    roles=db.all('SELECT id,name FROM roles')
    rid=[r['id'] for r in roles if r['name']=='Tesorería'][0]
    assert db.one("SELECT COUNT(*) n FROM role_permissions WHERE role_id=? AND permission='finanzas.editar'",(rid,))['n']==1
    resp=post(c,f'/permisos/{rid}',{'permissions':['socios.ver','finanzas.ver']})
    assert resp.status_code==303
    db.init()
    current={r['permission'] for r in db.all('SELECT permission FROM role_permissions WHERE role_id=?',(rid,))}
    assert current=={'socios.ver','finanzas.ver'}

def test_escaping_and_password_strength(environment):
    app,db,c,sid,*_=environment
    login(c)
    values={'name':'<script>alert(1)</script>','cedula':'','phone':'','email':'','joined':date.today().isoformat(),'notes':'x'}
    res=post(c,'/nuevo/socios',values)
    assert res.status_code==400
    assert '&lt;script&gt;' in res.text and '<script>alert' not in res.text
    short=post(c,'/nuevo/usuarios',{'full_name':'Usuario Prueba','username':'otro','email':'','role_id':'1','socio_id':'','password':'pass'})
    assert short.status_code==400


def test_socio_fields_are_validated_on_server_and_browser(environment):
    app,db,c,sid,*_=environment
    login(c)
    page=c.get('/nuevo/socios')
    assert 'maxlength="10" pattern="[0-9]{1,10}"' in page.text
    assert 'maxlength="10" pattern="[0-9]{10}"' in page.text
    assert 'type="email"' in page.text
    for field_name in ('cedula','phone','email'):
        assert re.search(rf'id="fld-{field_name}"[^>]*required',page.text)

    valid={'name':'María O’Neil','cedula':'12345678','phone':'0987654321',
           'email':'PERSONA@example.com','joined':date.today().isoformat(),'notes':''}
    for missing in ('name','cedula','phone','email','joined'):
        incomplete={key:value for key,value in valid.items() if key!=missing}
        response=post(c,'/nuevo/socios',incomplete)
        assert response.status_code==400
        assert f'aria-invalid="true" aria-describedby="error-{missing}"' in response.text
        assert db.one("SELECT COUNT(*) AS n FROM socios")['n']==2

    response=post(c,'/nuevo/socios',valid)
    assert response.status_code==303
    saved=db.one('SELECT name,cedula,phone,email FROM socios WHERE cedula=?',('12345678',))
    assert saved=={'name':'María O’Neil','cedula':'12345678','phone':'0987654321',
                   'email':'persona@example.com'}

    invalid_cases=[
        ('cedula','12345678901','hasta 10'),
        ('cedula','1234A','solo números'),
        ('phone','123456789','10 números'),
        ('phone','123456789a','10 números'),
        ('name','Juan3','solo letras'),
        ('name','Ana María!','solo letras'),
        ('email','persona@invalido','correo'),
    ]
    for key,value,message in invalid_cases:
        values={**valid,key:value}
        response=post(c,'/nuevo/socios',values)
        assert response.status_code==400
        assert message in response.text
        assert f'aria-invalid="true" aria-describedby="error-{key}"' in response.text

    duplicate=post(c,'/nuevo/socios',{**valid,'name':'Otra Persona'})
    assert duplicate.status_code==400
    assert 'aria-invalid="true" aria-describedby="error-cedula"' in duplicate.text
    assert db.one("SELECT COUNT(*) AS n FROM socios")['n']==3


def test_user_full_name_and_email_are_validated(environment):
    app,db,c,*_=environment
    login(c)
    common={'username':'usuario1','email':'no-es-correo','role_id':'1',
            'socio_id':'','password':'SecurePass123456'}
    invalid_name=post(c,'/nuevo/usuarios',{**common,'full_name':'Usuario 123'})
    assert invalid_name.status_code==400 and 'solo letras' in invalid_name.text
    invalid_email=post(c,'/nuevo/usuarios',{**common,'full_name':'Usuario Prueba','email':'mal-correo'})
    assert invalid_email.status_code==400 and 'correo' in invalid_email.text


def test_upload_document_magic_header_and_access(environment):
    app,db,c,sid,*_=environment
    login(c)
    with db.connection() as con:
        meeting_id=con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                               ('Consejo de Administración','Acta de prueba',date.today().isoformat(),'09:00','Sala')).lastrowid
    token=csrf(c,'/reunion/'+str(meeting_id))
    bad=c.post(f'/actas/{meeting_id}/archivo',data={'_csrf':token},files={'archivo':('invalido.pdf',b'not a pdf','application/pdf')})
    assert bad.status_code==400
    valid=c.post(f'/actas/{meeting_id}/archivo',data={'_csrf':token},files={'archivo':('ejemplo.pdf',b'%PDF-1.4\nDemo','application/pdf')},follow_redirects=False)
    assert valid.status_code==303
    d=db.one('SELECT * FROM docs ORDER BY id DESC LIMIT 1')
    assert c.get('/archivos/'+str(d['id'])).status_code==200


def test_money_values():
    assert money('50.50')==5050
    assert money('0.10')==10
    with pytest.raises(ValueError):money('1.235')
    with pytest.raises(ValueError):money('-10')
    with pytest.raises(ValueError):money('1;DROP TABLE debts')

def test_change_vehicle_generates_income(environment):
    app,db,c,sid,other,*_=environment
    with db.connection() as con:
        v1=con.execute('INSERT INTO vehicles(plate,brand,status) VALUES(?,?,?)',('AAA-0001','Hino','Activo')).lastrowid
        v2=con.execute('INSERT INTO vehicles(plate,brand,status) VALUES(?,?,?)',('BBB-0002','Hino','Activo')).lastrowid
        unit=con.execute('INSERT INTO units(code,socio_id,vehicle_id) VALUES(?,?,?)',('U-7',sid,v1)).lastrowid
    login(c)
    r=post(c,'/nuevo/cambios',{'unit_id':str(unit),'new_vehicle_id':str(v2),'reason':'Cambio autorizado','amount':'25.00',
                               'changed_at':date.today().isoformat(),'method':'Transferencia'})
    assert r.status_code==303
    assert db.one('SELECT vehicle_id FROM units WHERE id=?',(unit,))['vehicle_id']==v2
    income=db.one("SELECT amount_cents,category,method FROM incomes WHERE category='Cambio de vehículo' LIMIT 1")
    assert income=={'amount_cents':2500,'category':'Cambio de vehículo','method':'Transferencia'}


def test_unit_ownership_transfer_updates_owner_and_keeps_rights_history(environment):
    app,db,c,sid,other,*_=environment
    with db.connection() as con:
        unit=con.execute('INSERT INTO units(code,socio_id) VALUES(?,?)',('U-TRASPASO',sid)).lastrowid
    login(c)
    history_page=c.get('/socios?tab=traspasos')
    assert history_page.status_code==200 and 'Registrar traspaso' in history_page.text
    response=post(c,'/nuevo/traspasos',{
        'unit_id':str(unit),'new_socio_id':str(other),'transferred_at':date.today().isoformat(),
        'document_reference':'Contrato 2026-07','notes':'Venta acordada'
    })
    assert response.status_code==303
    assert db.one('SELECT socio_id FROM units WHERE id=?',(unit,))['socio_id']==other
    assert db.one('SELECT active FROM socios WHERE id=?',(sid,))['active']==0
    transfer=db.one('SELECT * FROM ownership_transfers WHERE unit_id=?',(unit,))
    assert transfer['from_socio_id']==sid and transfer['to_socio_id']==other
    assert transfer['includes_shares']==1 and transfer['includes_rights']==1
    assert transfer['document_reference']=='Contrato 2026-07'
    assert db.one("SELECT COUNT(*) n FROM audit WHERE entity='traspasos' AND record_id=?",(transfer['id'],))['n']==1
    history=c.get('/socios?tab=traspasos')
    assert 'Socio Uno' in history.text and 'Socio Dos' in history.text
    assert 'Bus, acciones y derechos' in history.text


def test_active_unit_rule_and_owner_change_require_transfer(environment):
    app,db,c,sid,other,*_=environment
    with db.connection() as con:
        unit=con.execute('INSERT INTO units(code,socio_id) VALUES(?,?)',('U-ACTIVA',sid)).lastrowid
        con.execute('INSERT INTO units(code,socio_id) VALUES(?,?)',('U-OTRA',other))
    login(c)
    duplicate=post(c,'/nuevo/unidades',{'code':'U-DUPLICADA','socio_id':str(sid),'vehicle_id':'','status':'Activa'})
    assert duplicate.status_code==400 and 'ya tiene otra unidad activa' in duplicate.text
    edit=post(c,f'/editar/unidades/{unit}',{
        'code':'U-ACTIVA','socio_id':str(other),'vehicle_id':'','status':'Activa'
    })
    assert edit.status_code==400 and 'registre un traspaso' in edit.text
    transfer=post(c,'/nuevo/traspasos',{
        'unit_id':str(unit),'new_socio_id':str(other),'transferred_at':date.today().isoformat(),
        'document_reference':'','notes':''
    })
    assert transfer.status_code==400 and 'ya tiene una unidad activa' in transfer.text
    assert db.one('SELECT socio_id FROM units WHERE id=?',(unit,))['socio_id']==sid
    assert db.one('SELECT active FROM socios WHERE id=?',(sid,))['active']==1
    assert db.one('SELECT COUNT(*) n FROM ownership_transfers')['n']==0


def test_user_role_change_revokes_existing_sessions(environment):
    app,db,c,sid,other,aid,vid,sid_user=environment
    with TestClient(app) as second:
        login(second,'vigilante')
        assert second.get('/multas').status_code==200
        assert second.get('/vigilancia').status_code==404
        login(c,'admin')
        secretary=db.one("SELECT id FROM roles WHERE name='Secretaría'")['id']
        r=post(c,f'/usuario/{vid}/rol',{'role_id':str(secretary)})
        assert r.status_code==303
        # The previously issued vigilante session is invalidated by role change.
        res=second.get('/multas',follow_redirects=False)
        assert res.status_code==303 and res.headers['location']=='/login'


def test_asistencia_view_and_selection(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea General', 'Reunión Ordinaria de Socios', today, '10:00', 'Auditorio')).lastrowid
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (mid, sid))
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (mid, other))
        con.execute('INSERT INTO attendance(meeting_id,socio_id,status) VALUES(?,?,?)', (mid, sid, 'Asistió'))
        con.execute('INSERT INTO attendance(meeting_id,socio_id,status) VALUES(?,?,?)', (mid, other, 'Faltó'))
    login(c, 'admin')

    # 1. Accessing /actas?tab=asistencia shows meeting selector with date, type, topic
    resp = c.get('/actas?tab=asistencia')
    assert resp.status_code == 200
    assert 'Seleccionar reunión' in resp.text
    assert f'{today} · Asamblea General · Reunión Ordinaria de Socios' in resp.text

    # 2. Accessing with meeting_id loads table and summary
    resp_meeting = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert resp_meeting.status_code == 200
    assert 'N.º' in resp_meeting.text
    assert 'Nombre del socio' in resp_meeting.text
    assert 'Unidad' in resp_meeting.text
    assert 'Asistió' in resp_meeting.text
    assert 'Guardar asistencia' in resp_meeting.text
    assert 'Marcar todos' in resp_meeting.text
    assert 'Socio Uno' in resp_meeting.text
    assert 'Socio Dos' in resp_meeting.text

    # 3. Checkboxes are pre-filled correctly according to SQLite
    assert f'value="{sid}" class="asistencia-check" aria-label="Asistió Socio Uno" checked' in resp_meeting.text
    assert f'value="{other}" class="asistencia-check" aria-label="Asistió Socio Dos"' in resp_meeting.text
    assert f'value="{other}" class="asistencia-check" aria-label="Asistió Socio Dos" checked' not in resp_meeting.text


def test_asistencia_save_and_no_duplication(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Consejo de Administración', 'Aprobación de rutas', today, '15:00', 'Oficina')).lastrowid
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (mid, sid))
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (mid, other))
    login(c, 'admin')

    # Initial save: both attend
    token = csrf(c, f'/actas?tab=asistencia&meeting_id={mid}')
    resp = c.post('/actas/asistencia', data={
        '_csrf': token,
        'meeting_id': str(mid),
        'all_socio_ids': [str(sid), str(other)],
        'asistio_ids': [str(sid), str(other)]
    }, follow_redirects=False)
    assert resp.status_code == 303
    assert f'/actas?tab=asistencia&meeting_id={mid}' in resp.headers['location']

    # Verify in SQLite: 2 records, both 'Asistió'
    records = db.all('SELECT * FROM attendance WHERE meeting_id=?', (mid,))
    assert len(records) == 2
    assert all(r['status'] == 'Asistió' for r in records)

    # Second save: uncheck 'other' (sid attends, other absents)
    token2 = csrf(c, f'/actas?tab=asistencia&meeting_id={mid}')
    resp2 = c.post('/actas/asistencia', data={
        '_csrf': token2,
        'meeting_id': str(mid),
        'all_socio_ids': [str(sid), str(other)],
        'asistio_ids': [str(sid)]
    }, follow_redirects=False)
    assert resp2.status_code == 303

    # Verify no duplication: still exactly 2 records!
    records2 = db.all('SELECT * FROM attendance WHERE meeting_id=?', (mid,))
    assert len(records2) == 2
    status_by_id = {r['socio_id']: r['status'] for r in records2}
    assert status_by_id[sid] == 'Asistió'
    assert status_by_id[other] == 'Faltó'

    # Check that reloading the page displays the saved checks correctly
    page = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert f'value="{sid}" class="asistencia-check" aria-label="Asistió Socio Uno" checked' in page.text
    assert f'value="{other}" class="asistencia-check" aria-label="Asistió Socio Dos" checked' not in page.text


def test_completed_meeting_creates_individual_absence_fines_once(environment):
    app,db,c,sid,other,*_=environment
    today=date.today().isoformat()
    with db.connection() as con:
        meeting_id=con.execute('''INSERT INTO meetings(type,topic,meeting_date,meeting_time,location)
            VALUES(?,?,?,?,?)''',('Asamblea General','Asamblea extraordinaria',today,'10:00','Sala')).lastrowid
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (meeting_id, sid))
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (meeting_id, other))
        con.execute('INSERT INTO attendance(meeting_id,socio_id,status) VALUES(?,?,?)',
                    (meeting_id,sid,'Faltó'))
        con.execute('INSERT INTO attendance(meeting_id,socio_id,status) VALUES(?,?,?)',
                    (meeting_id,other,'Justificó'))

    login(c,'admin')
    early=c.get(f'/reunion/{meeting_id}/multas-ausencias')
    assert early.status_code==200 and 'Marque la reunión como realizada' in early.text
    assert 'Generar multas' not in early.text

    completed=post(c,f'/reunion/{meeting_id}/realizada')
    assert completed.status_code==303
    detail=c.get(f'/reunion/{meeting_id}')
    assert 'Generar multas por inasistencia' in detail.text
    attendance_page=c.get(f'/actas?tab=asistencia&meeting_id={meeting_id}')
    assert 'Generar multas por inasistencia' in attendance_page.text
    assert 'Guardar asistencia' not in attendance_page.text

    fine_page=c.get(f'/reunion/{meeting_id}/multas-ausencias')
    assert fine_page.status_code==200 and 'Socio Uno' in fine_page.text
    assert 'Socio Dos' not in fine_page.text
    assert f'name="amount_{sid}"' in fine_page.text
    bad=post(c,f'/reunion/{meeting_id}/multas-ausencias',
             {'socio_ids':[str(sid)],f'amount_{sid}':'0'})
    assert bad.status_code==400 and 'mayor que cero' in bad.text
    assert db.one('SELECT COUNT(*) n FROM meeting_absence_fines WHERE meeting_id=?',
                  (meeting_id,))['n']==0

    created=post(c,f'/reunion/{meeting_id}/multas-ausencias',
                 {'socio_ids':[str(sid)],f'amount_{sid}':'25.50'})
    assert created.status_code==303
    link=db.one('SELECT * FROM meeting_absence_fines WHERE meeting_id=? AND socio_id=?',
                (meeting_id,sid))
    fine=db.one('SELECT * FROM fines WHERE id=?',(link['fine_id'],))
    debt=db.one('SELECT * FROM debts WHERE fine_id=?',(fine['id'],))
    assert fine['amount_cents']==2550 and fine['category']=='Inasistencia'
    assert fine['reason']=='Inasistencia a la reunión: Asamblea extraordinaria'
    assert debt['amount_cents']==2550 and debt['socio_id']==sid
    assert db.one('SELECT COUNT(*) n FROM fines WHERE socio_id=?',(other,))['n']==0
    assert db.one("SELECT COUNT(*) n FROM audit WHERE entity='multas' AND record_id=?",
                  (fine['id'],))['n']==1

    duplicate=post(c,f'/reunion/{meeting_id}/multas-ausencias',
                   {'socio_ids':[str(sid)],f'amount_{sid}':'25.50'})
    assert duplicate.status_code==400
    assert db.one('SELECT COUNT(*) n FROM meeting_absence_fines WHERE meeting_id=?',
                  (meeting_id,))['n']==1
    assert c.post('/actas/asistencia',data={'_csrf':csrf(c,'/perfil'),
        'meeting_id':str(meeting_id),'all_socio_ids':[str(sid),str(other)],
        'asistio_ids':[str(sid)]}).status_code==409


def test_asistencia_permissions_guard(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea Extraordinaria', 'Evaluación de tarifas', today, '11:00', 'Sala')).lastrowid
        con.execute('INSERT INTO meeting_notifications(meeting_id,socio_id,notified) VALUES(?,?,1)', (mid, sid))

    # Socio can view attendance, but cannot modify
    login(c, 'socio')
    resp = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert resp.status_code == 200
    assert 'disabled' in resp.text
    assert 'Guardar asistencia' not in resp.text
    assert 'Marcar todos' not in resp.text

    # Socio cannot POST to save attendance
    token = csrf(c, '/perfil')
    assert c.get(f'/reunion/{mid}/multas-ausencias').status_code==403
    forbidden_resp = c.post('/actas/asistencia', data={
        '_csrf': token,
        'meeting_id': str(mid),
        'all_socio_ids': [str(sid)],
        'asistio_ids': [str(sid)]
    })
    assert forbidden_resp.status_code == 403

def test_convocatoria_view_and_selection(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location,agenda) VALUES(?,?,?,?,?,?)',
                          ('Asamblea General', 'Convocatoria de prueba', today, '10:00', 'Auditorio', '1. Quorum\n2. Balance')).lastrowid
    login(c, 'admin')

    # 1. /actas?tab=convocatorias displays selector
    resp = c.get('/actas?tab=convocatorias')
    assert resp.status_code == 200
    assert 'Convocatorias a reuniones' in resp.text
    assert 'Seleccionar reunión' in resp.text
    assert 'Convocatoria de prueba' in resp.text

    # 2. Selecting meeting displays notice textarea and socios table
    resp_mid = c.get(f'/actas?tab=convocatorias&meeting_id={mid}')
    assert resp_mid.status_code == 200
    assert 'Texto de la convocatoria' in resp_mid.text
    assert 'Nombre del socio' in resp_mid.text
    assert 'Notificado' in resp_mid.text
    assert 'Socio Uno' in resp_mid.text
    assert 'Socio Dos' in resp_mid.text
    assert 'Guardar convocatoria y notificaciones' in resp_mid.text


def test_convocatoria_save_and_notifications(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Consejo de Administración', 'Aprobación presupuestaria', today, '16:00', 'Sala')).lastrowid
    login(c, 'admin')

    token = csrf(c, f'/actas?tab=convocatorias&meeting_id={mid}')
    notice_text = 'Estimados socios, se convoca a reunión extraordinaria.'
    oversized = c.post('/actas/convocatoria', data={
        '_csrf': token,
        'meeting_id': str(mid),
        'notice': 'x' * 5001,
        'all_socio_ids': [str(sid), str(other)],
        'notified_ids': [str(sid)]
    })
    assert oversized.status_code == 400
    assert db.one('SELECT notice FROM meetings WHERE id=?', (mid,))['notice'] == ''

    # sid is notified, other is NOT notified
    resp = c.post('/actas/convocatoria', data={
        '_csrf': token,
        'meeting_id': str(mid),
        'notice': notice_text,
        'all_socio_ids': [str(sid), str(other)],
        'notified_ids': [str(sid)]
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert 'Convocatoria y notificaciones guardadas correctamente' in resp.text

    # Verify meeting updated in SQLite
    m = db.one('SELECT notice, notice_sent_at FROM meetings WHERE id=?', (mid,))
    assert m['notice'] == notice_text
    assert m['notice_sent_at'] is not None

    # Verify meeting_notifications in SQLite
    notifs = db.all('SELECT socio_id, notified FROM meeting_notifications WHERE meeting_id=?', (mid,))
    assert len(notifs) == 2
    by_sid = {r['socio_id']: r['notified'] for r in notifs}
    assert by_sid[sid] == 1
    assert by_sid[other] == 0

    # Reloading shows sid checked as Notificado and other as No notificado
    page = c.get(f'/actas?tab=convocatorias&meeting_id={mid}')
    assert f'value="{sid}" data-badge="badge-notif-{sid}" class="convocatoria-check" aria-label="Notificado Socio Uno" checked' in page.text
    assert f'value="{other}" data-badge="badge-notif-{other}" class="convocatoria-check" aria-label="Notificado Socio Dos" checked' not in page.text


def test_convocatoria_permissions_guard(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea General', 'Reunión General', today, '09:00', 'Local')).lastrowid

    # Socio can view, but cannot modify
    login(c, 'socio')
    resp = c.get(f'/actas?tab=convocatorias&meeting_id={mid}')
    assert resp.status_code == 200
    assert 'disabled' in resp.text
    assert 'readonly' in resp.text
    assert 'Guardar convocatoria y notificaciones' not in resp.text

    # Socio cannot POST to save convocatoria
    token = csrf(c, '/perfil')
    forbidden = c.post('/actas/convocatoria', data={
        '_csrf': token,
        'meeting_id': str(mid),
        'notice': 'Intento no autorizado',
        'all_socio_ids': [str(sid)],
        'notified_ids': [str(sid)]
    })
    assert forbidden.status_code == 403


def test_convocatoria_multiline_and_special_chars(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea General', 'Reunión Extraordinaria', today, '10:00', 'Auditorio')).lastrowid
    login(c, 'admin')

    token = csrf(c, f'/actas?tab=convocatorias&meeting_id={mid}')
    multiline_notice = (
        "Estimados socios de la cooperativa:\r\n\r\n"
        "Se les convoca a la reunión ordinaria de año nuevo.\r\n"
        "Orden del día:\r\n"
        "1. Constatación del quórum reglamentario.\r\n"
        "2. Lectura y aprobación del acta anterior.\r\n"
        "3. Informe financiero y asignación de unidades (año 2026).\r\n"
        "¿Preguntas o sugerencias? ¡Favor asistir puntualmente a las 10:00 AM!\r\n\r\n"
        "Atentamente,\r\n"
        "La Presidencia y Secretaría General — Cooperativa Guaytacama."
    )

    resp = c.post('/actas/convocatoria', data={
        '_csrf': token,
        'meeting_id': str(mid),
        'notice': multiline_notice,
        'all_socio_ids': [str(sid), str(other)],
        'notified_ids': [str(sid)]
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert 'Convocatoria y notificaciones guardadas correctamente' in resp.text

    m = db.one('SELECT notice FROM meetings WHERE id=?', (mid,))
    assert m['notice'] is not None
    assert '¿Preguntas o sugerencias? ¡Favor asistir puntualmente a las 10:00 AM!' in m['notice']
    assert 'año 2026' in m['notice']
    assert '\n' in m['notice']


def test_asistencia_only_shows_and_saves_notified_socios(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea General', 'Reunión Selectiva de Socios', today, '11:00', 'Sala')).lastrowid
    login(c, 'admin')

    # 1. Before saving any convocatoria notification, meeting has 0 notified socios
    asistencia_empty = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert asistencia_empty.status_code == 200
    assert 'No hay socios convocados para esta reunión' in asistencia_empty.text
    assert 'Socio Uno' not in asistencia_empty.text
    assert 'Socio Dos' not in asistencia_empty.text

    # 2. Save convocatoria with ONLY 'sid' notified
    token_conv = csrf(c, f'/actas?tab=convocatorias&meeting_id={mid}')
    resp_conv = c.post('/actas/convocatoria', data={
        '_csrf': token_conv,
        'meeting_id': str(mid),
        'notice': 'Convocatoria para socio uno únicamente.\r\n¡Por favor asistir!',
        'all_socio_ids': [str(sid), str(other)],
        'notified_ids': [str(sid)]
    }, follow_redirects=True)
    assert resp_conv.status_code == 200

    # 3. Asistencia now lists ONLY 'sid', NOT 'other'
    asistencia_page = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert asistencia_page.status_code == 200
    assert 'Socio Uno' in asistencia_page.text
    assert 'Socio Dos' not in asistencia_page.text
    assert f'value="{sid}" class="asistencia-check"' in asistencia_page.text
    assert f'value="{other}" class="asistencia-check"' not in asistencia_page.text

    # 4. Save attendance for the notified socio
    token_asist = csrf(c, f'/actas?tab=asistencia&meeting_id={mid}')
    resp_asist = c.post('/actas/asistencia', data={
        '_csrf': token_asist,
        'meeting_id': str(mid),
        'all_socio_ids': [str(sid)],
        'asistio_ids': [str(sid)]
    }, follow_redirects=True)
    assert resp_asist.status_code == 200

    # Verify SQLite: only 'sid' has an attendance record
    att_records = db.all('SELECT socio_id, status FROM attendance WHERE meeting_id=?', (mid,))
    assert len(att_records) == 1
    assert att_records[0]['socio_id'] == sid
    assert att_records[0]['status'] == 'Asistió'

    # 5. If we un-notify 'sid' in convocatoria, attendance is cleaned up
    token_conv2 = csrf(c, f'/actas?tab=convocatorias&meeting_id={mid}')
    resp_conv2 = c.post('/actas/convocatoria', data={
        '_csrf': token_conv2,
        'meeting_id': str(mid),
        'notice': 'Ningún socio notificado.',
        'all_socio_ids': [str(sid), str(other)],
        'notified_ids': []
    }, follow_redirects=True)
    assert resp_conv2.status_code == 200

    # In SQLite, attendance record was removed because socio is no longer notified
    assert db.all('SELECT * FROM attendance WHERE meeting_id=?', (mid,)) == []
    # And page shows empty state
    page_now = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert 'No hay socios convocados para esta reunión' in page_now.text



def test_auditoria_module_only_admin(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment

    # 1. Unauthenticated cannot access /auditoria
    anon_resp = c.get('/auditoria', follow_redirects=False)
    assert anon_resp.status_code == 303
    assert anon_resp.headers['location'] == '/login'

    # 2. Socio cannot access /auditoria (Forbidden 403)
    login(c, 'socio')
    socio_resp = c.get('/auditoria')
    assert socio_resp.status_code == 403

    # 3. Vigilancia cannot access /auditoria (Forbidden 403)
    assert post(c, '/logout').status_code == 303
    login(c, 'vigilante')
    vig_resp = c.get('/auditoria')
    assert vig_resp.status_code == 403

    # 4. Administrador can access /auditoria and all its tabs
    assert post(c, '/logout').status_code == 303
    login(c, 'admin')
    admin_resp = c.get('/auditoria')
    assert admin_resp.status_code == 200
    assert 'Historial del sistema' in admin_resp.text
    assert 'Todo el historial' in admin_resp.text
    assert 'Inicios y accesos' in admin_resp.text
    assert 'Operaciones' in admin_resp.text
    assert 'Seguridad' in admin_resp.text

    # Check subtabs
    for tab in ['logins', 'operaciones', 'seguridad', 'todos']:
        tab_resp = c.get(f'/auditoria?tab={tab}')
        assert tab_resp.status_code == 200
        assert 'Total eventos' in tab_resp.text
        assert 'IP del dispositivo' in tab_resp.text


def test_audit_logs_logins_and_system_events(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment

    # 1. Failed login is recorded in audit with IP
    token = csrf(c, '/login')
    fail_resp = c.post('/login', data={'_csrf': token, 'username': 'admin', 'password': 'WrongPassword123!'}, follow_redirects=False)
    assert fail_resp.status_code == 401
    fail_audit = db.one("SELECT * FROM audit WHERE action='Intento fallido' ORDER BY id DESC LIMIT 1")
    assert fail_audit is not None
    assert 'admin' in fail_audit['summary']
    assert fail_audit['ip_address'] is not None

    # 2. Successful login is recorded with IP
    token = csrf(c, '/login')
    success_resp = c.post('/login', data={'_csrf': token, 'username': 'admin', 'password': 'SecurePass123456'}, follow_redirects=False)
    assert success_resp.status_code == 303
    login_audit = db.one("SELECT * FROM audit WHERE action='Inicio de sesión' ORDER BY id DESC LIMIT 1")
    assert login_audit is not None
    assert login_audit['user_id'] == aid
    assert login_audit['ip_address'] is not None

    # 3. Operation is recorded with summary and IP
    r = post(c, '/nuevo/socios', {'name': 'Socio Auditoria', 'cedula': '1700000000', 'phone': '0999999999', 'email': 'auditoria@example.com', 'joined': date.today().isoformat(), 'notes': 'Test'})
    assert r.status_code == 303
    socio_audit = db.one("SELECT * FROM audit WHERE entity='socios' ORDER BY id DESC LIMIT 1")
    assert socio_audit is not None
    assert 'Socio Auditoria' in socio_audit['summary']
    assert socio_audit['ip_address'] is not None

    # 4. View in /auditoria?tab=logins shows IP del dispositivo column
    audit_page = c.get('/auditoria?tab=logins')
    assert audit_page.status_code == 200
    assert 'IP del dispositivo' in audit_page.text
    assert 'Inicio de sesión' in audit_page.text
    assert 'Intento fallido' in audit_page.text


def test_multas_pay_flow_and_pagadas_tab(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    login(c, 'admin')
    today = date.today().isoformat()

    # 1. Registrar una nueva multa
    r = post(c, '/nuevo/multas', {
        'socio_id': str(sid),
        'unit_id': '',
        'category': 'Atraso',
        'reason': 'Atraso en turno matutino',
        'occurred_at': today,
        'amount': '35.00'
    })
    assert r.status_code == 303
    fine = db.one("SELECT * FROM fines WHERE reason='Atraso en turno matutino'")
    assert fine is not None
    assert fine['status'] == 'Pendiente'

    # 2. En la pestaña de pendientes aparece el botón de Pagar y el de Registrar multa
    page_pend = c.get('/multas?tab=pendientes')
    assert page_pend.status_code == 200
    assert f'/multas/{fine["id"]}/pagar' in page_pend.text
    assert '✓ Registrar abono' in page_pend.text
    assert 'Registrar multa' in page_pend.text

    # 3. En la pestaña de pagadas NO aparece el botón de Registrar multa ni la multa pendiente
    page_paid = c.get('/multas?tab=pagadas')
    assert page_paid.status_code == 200
    assert 'Registrar multa' not in page_paid.text
    assert 'Atraso en turno matutino' not in page_paid.text

    # 4. GET /multas/{id}/pagar muestra pantalla de cobro
    get_pay = c.get(f'/multas/{fine["id"]}/pagar')
    assert get_pay.status_code == 200
    assert 'Cobrar y pagar multa' in get_pay.text
    assert 'app-confirm-dialog' in get_pay.text
    assert 'data-confirm=' in get_pay.text
    assert '35.00' in get_pay.text

    # 5. POST /multas/{id}/pagar registra el pago
    token = csrf(c, f'/multas/{fine["id"]}/pagar')
    pay_resp = c.post(f'/multas/{fine["id"]}/pagar', data={
        '_csrf': token,
        'method': 'Transferencia',
        'day': today,
        'notes': 'Cobrado en ventanilla'
    }, follow_redirects=False)
    assert pay_resp.status_code == 303
    assert '/multas?tab=pagadas' in pay_resp.headers['location']

    # 6. Verificar en base de datos: estado Pagada, deuda saldada, pago registrado
    f_updated = db.one('SELECT * FROM fines WHERE id=?', (fine['id'],))
    assert f_updated['status'] == 'Pagada'
    d_updated = db.one('SELECT * FROM debts WHERE fine_id=?', (fine['id'],))
    assert d_updated['paid_cents'] == 3500
    pay_record = db.one('SELECT * FROM payments WHERE debt_id=?', (d_updated['id'],))
    assert pay_record is not None
    assert pay_record['amount_cents'] == 3500
    assert pay_record['method'] == 'Transferencia'

    # 7. Ahora la multa aparece en /multas?tab=pagadas y NO hay botón de Registrar multa
    page_paid_after = c.get('/multas?tab=pagadas')
    assert page_paid_after.status_code == 200
    assert 'Atraso en turno matutino' in page_paid_after.text
    assert 'Registrar multa' not in page_paid_after.text

    # 8. Unificación: solo se usa el término Multas y no Sanciones, vigilancia obsoleta da 404
    multas_page = c.get('/multas')
    assert multas_page.status_code == 200
    assert 'Sanciones' not in multas_page.text
    assert c.get('/vigilancia').status_code == 404


def test_configuracion_only_admin_and_saves_settings(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment

    # 1. Unauthenticated cannot access /configuracion
    anon_resp = c.get('/configuracion', follow_redirects=False)
    assert anon_resp.status_code == 303
    assert anon_resp.headers['location'] == '/login'

    # 2. Socio cannot access /configuracion (Forbidden 403)
    login(c, 'socio')
    socio_resp = c.get('/configuracion')
    assert socio_resp.status_code == 403

    # 3. Vigilante cannot access /configuracion (Forbidden 403)
    assert post(c, '/logout').status_code == 303
    login(c, 'vigilante')
    vig_resp = c.get('/configuracion')
    assert vig_resp.status_code == 403

    # 4. Administrador can access /configuracion
    assert post(c, '/logout').status_code == 303
    login(c, 'admin')
    admin_resp = c.get('/configuracion')
    assert admin_resp.status_code == 200
    assert 'Configurar página' in admin_resp.text
    assert 'cfg-company-name' in admin_resp.text
    assert 'live-mockup-frame' in admin_resp.text
    assert 'bus-transition-overlay' in admin_resp.text

    # 5. Admin saves new settings
    token = csrf(c, '/configuracion')
    save_resp = c.post('/configuracion', data={
        '_csrf': token,
        'company_name': 'Cooperativa San Cristóbal',
        'company_slogan': 'Rutas del Austro',
        'primary_color': '#b91c1c',
        'sidebar_color': '#1e293b',
        'accent_color': '#f59e0b',
        'font_family': 'Inter, system-ui, sans-serif',
        'bus_animation': '1',
        'animation_duration': '1.8',
        'footer_text': 'Cooperativa San Cristóbal · 2026'
    }, follow_redirects=False)
    assert save_resp.status_code == 303

    # Verify saved settings in database
    s = db.get_settings()
    assert s['company_name'] == 'Cooperativa San Cristóbal'
    assert s['primary_color'] == '#b91c1c'
    assert s['sidebar_color'] == '#1e293b'

    # Verify audit log
    audit_row = db.one("SELECT * FROM audit WHERE action='Configurar sistema' ORDER BY id DESC LIMIT 1")
    assert audit_row is not None
    assert audit_row['ip_address'] is not None

    # Verify page reflects new settings
    new_page = c.get('/configuracion')
    assert 'Cooperativa San Cristóbal' in new_page.text

    # 6. Admin can reset to defaults
    token_reset = csrf(c, '/configuracion')
    reset_resp = c.post('/configuracion/reset', data={'_csrf': token_reset}, follow_redirects=False)
    assert reset_resp.status_code == 303
    s_reset = db.get_settings()
    assert s_reset['company_name'] == 'Compañía de Transportes Guaytacama'


def test_weekly_marks_are_created_searched_and_paid_as_income(environment):
    app,db,c,sid,other,*_=environment
    today=date.today().isoformat()
    login(c)
    form=c.get('/marcaciones/nueva')
    assert form.status_code==200 and 'Socio Uno' in form.text and 'Socio Dos' in form.text
    assert 'name="amount"' in form.text and f'name="amount_{sid}"' not in form.text
    created=post(c,'/marcaciones/nueva',{'week_start':today,
        'amount':'12.50'})
    assert created.status_code==303
    marks=db.all('SELECT * FROM weekly_marks WHERE week_start=? ORDER BY socio_id',(today,))
    assert [mark['amount_cents'] for mark in marks]==[1250,1250]
    assert all(mark['state']=='Pendiente' for mark in marks)
    assert all(mark['paid_cents']==0 for mark in marks)
    duplicate_create=post(c,'/marcaciones/nueva',{'week_start':today,
        'amount':'20'})
    assert duplicate_create.status_code==400
    assert db.one('SELECT COUNT(*) AS n FROM weekly_marks WHERE week_start=?',(today,))['n']==2

    history=c.get(f'/finanzas?tab=marcaciones&desde={today}&hasta={today}')
    assert history.status_code==200
    assert 'Socios y estado de pago' not in history.text
    assert 'Ver lista' in history.text and 'S/ 25.00' in history.text
    history=c.get(f'/finanzas?tab=marcaciones&desde={today}&hasta={today}&lista=1')
    assert 'Socio Uno' in history.text and 'Socio Dos' in history.text
    assert history.text.count('12.50') >= 2 and '>Pagar</button>' in history.text
    assert 'btn success small' in history.text and 'weekly-payment-form' in history.text
    assert '<th>Medio</th>' not in history.text
    assert 'weekly-payment-form' in history.text and 'weekly-date-filter' in history.text
    assert 'weekly-status-filter' in history.text

    partial=post(c,f'/marcaciones/{marks[0]["id"]}/pagar',
        {'amount':'5.00'})
    assert partial.status_code==303
    mark=db.one('SELECT * FROM weekly_marks WHERE id=?',(marks[0]['id'],))
    income=db.one('SELECT * FROM incomes WHERE id=?',(mark['income_id'],))
    assert mark['state']=='Pendiente' and mark['paid_cents']==500
    assert mark['payment_method']=='Efectivo'
    assert income['category']=='Marcación semanal'
    assert income['amount_cents']==500 and income['socio_id']==sid
    assert income['method']=='Efectivo' and income['day']==today
    assert db.one("SELECT COUNT(*) AS n FROM incomes WHERE category='Marcación semanal'")['n']==1
    overpayment=post(c,f'/marcaciones/{marks[0]["id"]}/pagar',
        {'amount':'8.00'})
    assert overpayment.status_code==400
    completed=post(c,f'/marcaciones/{marks[0]["id"]}/pagar',
        {'amount':'7.50'})
    assert completed.status_code==303
    mark=db.one('SELECT * FROM weekly_marks WHERE id=?',(marks[0]['id'],))
    assert mark['state']=='Pagado' and mark['paid_cents']==1250
    assert db.one("SELECT COUNT(*) AS n FROM incomes WHERE category='Marcación semanal'")['n']==2
    duplicate=post(c,f'/marcaciones/{marks[0]["id"]}/pagar',
        {'amount':'1.00'})
    assert duplicate.status_code==400

    searched=c.get(f'/finanzas?tab=marcaciones&desde={today}&hasta={today}&lista=1')
    assert 'Total recaudado' in searched.text and 'Pagado' in searched.text
    assert 'Pendiente' in searched.text and '>Pagar</button>' in searched.text
    paid_only=c.get(f'/finanzas?tab=marcaciones&desde={today}&hasta={today}&lista=1&estado=Pagado')
    assert 'Socio Uno' in paid_only.text and 'Socio Dos' not in paid_only.text
    pending_only=c.get(f'/finanzas?tab=marcaciones&desde={today}&hasta={today}&lista=1&estado=Pendiente')
    assert 'Socio Dos' in pending_only.text and 'Socio Uno' not in pending_only.text
    assert 'value="Pendiente" selected' in pending_only.text
    assert c.get('/finanzas?tab=marcaciones&desde=invalid').status_code==400
    assert c.get(f'/finanzas?tab=marcaciones&lista=1&estado=Invalido').status_code==400
    assert c.get('/finanzas?tab=marcaciones&desde=2025-02-02&hasta=2025-02-01').status_code==400


def test_weekly_marks_require_positive_values_and_are_private_to_socio(environment):
    app,db,c,sid,other,*_=environment
    today=date.today().isoformat()
    login(c)
    invalid=post(c,'/marcaciones/nueva',{'week_start':today,
        'amount':'0'})
    assert invalid.status_code==400 and 'mayor que cero' in invalid.text
    assert db.one('SELECT COUNT(*) AS n FROM weekly_marks')['n']==0

    period=db.current_period()
    with db.connection() as con:
        con.execute('''INSERT INTO weekly_marks
            (period_id,socio_id,week_start,concept,amount_cents,state)
            VALUES(?,?,?,?,?,'Pendiente')''',(period['id'],sid,today,'Marcación semanal',1000))
        con.execute('''INSERT INTO weekly_marks
            (period_id,socio_id,week_start,concept,amount_cents,state)
            VALUES(?,?,?,?,?,'Pendiente')''',(period['id'],other,today,'Marcación semanal',2000))
    login(c,'socio')
    history=c.get(f'/finanzas?tab=marcaciones&desde={today}&hasta={today}&lista=1')
    assert history.status_code==200 and 'Socio Uno' in history.text
    assert 'Socio Dos' not in history.text
    assert '>Pagar</button>' not in history.text


def test_weekly_marks_migration_backfills_paid_amount(tmp_path):
    database=sqlite3.connect(tmp_path/'legacy.sqlite3')
    database.row_factory=sqlite3.Row
    database.execute('''CREATE TABLE weekly_marks (
        id INTEGER PRIMARY KEY, period_id INTEGER, socio_id INTEGER, week_start TEXT,
        concept TEXT, amount_cents INTEGER, state TEXT)''')
    database.execute('''INSERT INTO weekly_marks
        (period_id,socio_id,week_start,concept,amount_cents,state)
        VALUES(1,1,'2026-11-09','Marcación semanal',2500,'Pagado')''')

    Database.migrate_weekly_marks(database)

    mark=database.execute('SELECT paid_cents FROM weekly_marks').fetchone()
    assert mark['paid_cents']==2500
    database.close()


def test_weekly_pending_totals_sum_all_selected_dates_and_partial_payments(environment):
    app,db,c,sid,other,*_=environment
    login(c)
    yesterday=(date.today()-timedelta(days=1)).isoformat()
    today=date.today().isoformat()
    for day,amount in ((yesterday,'10.00'),(today,'20.00')):
        created=post(c,'/marcaciones/nueva',{'week_start':day,'amount':amount})
        assert created.status_code==303

    older_mark=db.one('SELECT id FROM weekly_marks WHERE week_start=? AND socio_id=?',(yesterday,sid))
    partial=post(c,f'/marcaciones/{older_mark["id"]}/pagar',
        {'amount':'5.00'})
    assert partial.status_code==303

    history=c.get(f'/finanzas?tab=marcaciones&desde={yesterday}&hasta={today}')
    assert history.status_code==200 and 'S/ 55.00' in history.text
    assert 'S/ 15.00' in history.text and 'S/ 40.00' in history.text
