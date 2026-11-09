"""Security and data-integrity regression tests. Run: python -m pytest -q"""
import re
from datetime import date
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
    r=c.get('/unidades')
    assert 'U-001' in r.text and 'U-999' not in r.text
    assert c.get('/nuevo/deudas').status_code==403
    assert c.get('/reportes').status_code==403

def test_report_outputs_and_period_close_guard(environment):
    app,db,c,*_=environment
    login(c)
    pdf=c.get('/reporte/general.pdf')
    assert pdf.status_code==200 and pdf.content.startswith(b'%PDF-')
    csv=c.get('/reporte/deudas.csv')
    assert csv.status_code==200 and csv.content.startswith(b'\xef\xbb\xbf')
    period=db.current_period()
    from datetime import date as dt
    if dt.today()<dt.fromisoformat(period['ends']):
        resp=post(c,'/cierre',{'confirmacion':'CERRAR '+period['label']})
        assert resp.status_code==400
        assert db.one('SELECT closed_at FROM periods WHERE id=?',(period['id'],))['closed_at'] is None

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
    assert res.status_code==303
    response=c.get('/socios')
    assert '&lt;script&gt;' in response.text and '<script>alert' not in response.text
    short=post(c,'/nuevo/usuarios',{'full_name':'Usuario Prueba','username':'otro','email':'','role_id':'1','socio_id':'','password':'pass'})
    assert short.status_code==400


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


def test_user_role_change_revokes_existing_sessions(environment):
    app,db,c,sid,other,aid,vid,sid_user=environment
    with TestClient(app) as second:
        login(second,'vigilante')
        assert second.get('/vigilancia').status_code==200
        login(c,'admin')
        secretary=db.one("SELECT id FROM roles WHERE name='Secretaría'")['id']
        r=post(c,f'/usuario/{vid}/rol',{'role_id':str(secretary)})
        assert r.status_code==303
        # The previously issued vigilante session is invalidated by role change.
        res=second.get('/vigilancia',follow_redirects=False)
        assert res.status_code==303 and res.headers['location']=='/login'


def test_asistencia_view_and_selection(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea General', 'Reunión Ordinaria de Socios', today, '10:00', 'Auditorio')).lastrowid
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


def test_asistencia_permissions_guard(environment):
    app, db, c, sid, other, aid, vid, sid_user = environment
    today = date.today().isoformat()
    with db.connection() as con:
        mid = con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location) VALUES(?,?,?,?,?)',
                          ('Asamblea Extraordinaria', 'Evaluación de tarifas', today, '11:00', 'Sala')).lastrowid

    # Socio can view attendance, but cannot modify
    login(c, 'socio')
    resp = c.get(f'/actas?tab=asistencia&meeting_id={mid}')
    assert resp.status_code == 200
    assert 'disabled' in resp.text
    assert 'Guardar asistencia' not in resp.text
    assert 'Marcar todos' not in resp.text

    # Socio cannot POST to save attendance
    token = csrf(c, '/perfil')
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

