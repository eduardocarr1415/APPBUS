"""Administration CLI: initialize administrator, add synthetic demo data, backup database."""
import argparse
import secrets
import shutil
from datetime import date, timedelta
from pathlib import Path
from app.db import Database
from app.security import password_hash
from app import ROOT

DB = Database(ROOT/'instance'/'buses.sqlite3')

def init():
    DB.init()
    first=DB.one('SELECT id FROM users LIMIT 1')
    if first:
        print('La base de datos ya está inicializada y existen cuentas. No se cambió ninguna contraseña.')
        return
    password=secrets.token_urlsafe(18)
    with DB.connection() as con:
        role=con.execute("SELECT id FROM roles WHERE name='Administrador'").fetchone()['id']
        con.execute('INSERT INTO users(username,full_name,email,password_hash,role_id) VALUES(?,?,?,?,?)',
                    ('admin','Administrador principal',None,password_hash(password),role))
        Database.audit(con,None,'Inicializar','sistema',None,'Se creó el primer administrador.')
    print('\n'+'='*54)
    print('ACCESO INICIAL - GUARDAR DE FORMA SEGURA')
    print('Usuario: admin')
    print('Contraseña generada: '+password)
    print('La contraseña NO queda guardada en un archivo de texto.')
    print('CAMBIE LA CONTRASEÑA DESDE MI PERFIL.')
    print('='*54+'\n')

def demo():
    DB.init()
    if not DB.one('SELECT id FROM users LIMIT 1'):
        print('Primero ejecute: python manage.py init');return
    if DB.one("SELECT id FROM socios WHERE name='Juan Pérez (Demo)'"):
        print('Datos de demostración ya cargados; no se duplicaron.');return
    today=date.today(); period=DB.current_period()
    base=max(date.fromisoformat(period['starts']),today-timedelta(days=100))
    day=lambda offset: (min(date.fromisoformat(period['ends']),base+timedelta(days=offset))).isoformat()
    socios=[('Juan Pérez (Demo)','0990001001'),('María Torres (Demo)','0990001002'),('Luis Gómez (Demo)','0990001003'),
           ('Pedro Vargas (Demo)','0990001004'),('Ana Condori (Demo)','0990001005'),('Carlos Ruiz (Demo)','0990001006'),
           ('Elena Paredes (Demo)','0990001007'),('Diego Flores (Demo)','0990001008')]
    with DB.connection() as con:
        user_id=con.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        uid=user_id['id'] if user_id else con.execute('SELECT id FROM users ORDER BY id LIMIT 1').fetchone()['id']
        socioids=[]
        for i,(name,phone) in enumerate(socios,1):
            socioids.append(con.execute('INSERT INTO socios(name,cedula,phone,joined) VALUES(?,?,?,?)',
                            (name,f'00000000{i:02d}',phone,day(0))).lastrowid)
        vehicleids=[]
        for plate,brand,model in [('ABC-1201','Hino','AK'),('ABC-1202','Mercedes-Benz','OF'),('ABC-1203','Hyundai','County'),
                                  ('ABC-1204','Hino','AK'),('ABC-1205','Volvo','B8R'),('ABC-1206','Mercedes-Benz','OF')]:
            vehicleids.append(con.execute('INSERT INTO vehicles(plate,brand,model,year,status) VALUES(?,?,?,?,?)',
                                         (plate,brand,model,2020,'Activo')).lastrowid)
        unitids=[]
        for i in range(6):
            unitids.append(con.execute('INSERT INTO units(code,socio_id,vehicle_id,status) VALUES(?,?,?,?)',
                                      (f'U-{i+1:03d}',socioids[i],vehicleids[i],'Activa')).lastrowid)
        meetings=[]
        for typ,topic,dt in [('Consejo de Administración','Revisión de gestión y presupuesto',day(2)),
                             ('Asamblea General','Informe económico y aprobación de actas',day(12)),
                             ('Asamblea Extraordinaria','Organización de las unidades',day(20))]:
            meetings.append(con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location,agenda,status,notice,notice_sent_at,minutes,minutes_state,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                                        (typ,topic,dt,'10:00','Sala de reuniones','1. Informe de actividades.\n2. Acuerdos y compromisos.','Realizada',
                                         'Convocatoria disponible para los socios.',dt+' 09:00:00','Se revisaron los temas previstos y se registraron los acuerdos.','Aprobada',uid)).lastrowid)
        if today < date.fromisoformat(period['ends']):
            next_date=min(today+timedelta(days=7),date.fromisoformat(period['ends'])).isoformat()
            con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location,agenda,status,notice,created_by) VALUES(?,?,?,?,?,?,?,?,?)',
                        ('Asamblea General','Próxima asamblea de socios',next_date,'10:00','Sala de reuniones',
                         '1. Registro de asistencia.\n2. Informe de gestión.','Programada','Convocatoria por confirmar.',uid))
        for mid in meetings:
            for i,sid in enumerate(socioids):
                con.execute('INSERT INTO attendance(meeting_id,socio_id,status) VALUES(?,?,?)',
                            (mid,sid,'Asistió' if i%5 else 'Justificó'))
        for i,amount in enumerate([250000,180000,320000,125000,99000,410000,140000]):
            con.execute('INSERT INTO incomes(period_id,socio_id,concept,category,amount_cents,method,day,created_by) VALUES(?,?,?,?,?,?,?,?)',
                        (period['id'],socioids[i%8],['Aporte mensual','Servicio de ruta','Aporte extraordinario'][i%3],
                         ['Aporte','Servicio','Otros'][i%3],amount,'Transferencia' if i%2 else 'Efectivo',day([2,18,35,52,66,81,95][i]),uid))
        for i,sid in enumerate(socioids[:5]):
            amt=(i+1)*8000
            con.execute('INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued,created_by) VALUES(?,?,?,?,?,?)',
                        (period['id'],sid,'Aporte pendiente (Demo)',amt,day(i+2),uid))
        for i in range(4):
            amt=[5000,3000,4000,2500][i]
            fid=con.execute('INSERT INTO fines(period_id,socio_id,unit_id,category,reason,occurred_at,amount_cents,created_by) VALUES(?,?,?,?,?,?,?,?)',
                             (period['id'],socioids[i],unitids[i],['Atraso','Radio','Minutos','Trabajo'][i],
                              ['Atraso en salida','Uso indebido de radio','Retraso por minutos','Incumplimiento de trabajo'][i],day(i+5),amt,uid)).lastrowid
            con.execute('INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued,fine_id,created_by) VALUES(?,?,?,?,?,?,?)',
                        (period['id'],socioids[i],'Multa de demostración',amt,day(i+5),fid,uid))
        debt=con.execute('SELECT id,socio_id,amount_cents FROM debts WHERE fine_id IS NULL LIMIT 1').fetchone()
        con.execute('INSERT INTO payments(period_id,debt_id,socio_id,amount_cents,method,day,created_by) VALUES(?,?,?,?,?,?,?)',
                    (period['id'],debt['id'],debt['socio_id'],2000,'Efectivo',day(11),uid))
        con.execute('UPDATE debts SET paid_cents=paid_cents+2000 WHERE id=?',(debt['id'],))
        for i,sid in enumerate(socioids[:6]):
            con.execute('INSERT INTO weekly_marks(period_id,socio_id,week_start,concept,amount_cents,state,created_by) VALUES(?,?,?,?,?,?,?)',
                        (period['id'],sid,day(0),'Marcación semanal (Demo)',500 if i%2 else 0,'Marcado',uid))
        for i in range(3):
            con.execute('INSERT INTO vigilance(period_id,socio_id,unit_id,category,details,day,created_by) VALUES(?,?,?,?,?,?,?)',
                        (period['id'],socioids[i],unitids[i],'Control de trabajo','Revisión administrativa de demostración.',day(i+8),uid))
        # Create separate test accounts with unique random passwords, never hardcoded defaults.
        credentials=[]
        for username,fullname,rol,sid in [('secretaria_demo','Secretaría (Demo)','Secretaría',None),
                                           ('tesoreria_demo','Tesorería (Demo)','Tesorería',None),
                                           ('vigilancia_demo','Vigilancia (Demo)','Vigilancia',None),
                                           ('socio_demo','Juan Pérez (Demo)','Socio',socioids[0])]:
            pwd=secrets.token_urlsafe(18)
            rid=con.execute('SELECT id FROM roles WHERE name=?',(rol,)).fetchone()['id']
            con.execute('INSERT INTO users(username,full_name,password_hash,role_id,socio_id) VALUES(?,?,?,?,?)',
                        (username,fullname,password_hash(pwd),rid,sid))
            credentials.append((username,pwd,rol))
        Database.audit(con,uid,'Cargar','demostracion',None,'Datos ficticios; no representan información real.')
    print('Datos ficticios agregados correctamente: 8 socios, 6 unidades, reuniones, ingresos, multas y pagos.')
    print('CREDENCIALES TEMPORALES DE DEMOSTRACIÓN (GUÁRDELAS):')
    for username,pwd,rol in credentials:
        print(f'  {rol:12s} | usuario: {username:17s} | contraseña: {pwd}')
    print('Las claves se muestran una vez y solo se almacenan como hash seguro.')

def backup():
    DB.init()
    dest=ROOT/'copias_seguridad'
    dest.mkdir(exist_ok=True)
    stamp=date.today().isoformat()
    target=dest/f'buses_backup_{stamp}_{secrets.token_hex(3)}.sqlite3'
    # SQLite backup API safely captures WAL state without copying a live file blindly.
    import sqlite3
    src=sqlite3.connect(DB.path)
    dst=sqlite3.connect(target)
    with dst:src.backup(dst)
    src.close();dst.close()
    print('Copia de seguridad:',target)

def reset_admin():
    DB.init()
    admin = DB.one("SELECT id FROM users WHERE username='admin'")
    if not admin:
        print("El usuario admin no existe.")
        return
    password = 'Admin12345678!'
    with DB.connection() as con:
        con.execute("UPDATE users SET password_hash=?, session_version=session_version+1 WHERE username='admin'", (password_hash(password),))
        con.execute("DELETE FROM sessions WHERE user_id=?", (admin['id'],))
    print(f"\nContraseña de 'admin' restablecida a: {password}\n")

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Administrar el sistema de buses')
    parser.add_argument('command',choices=['init','demo','backup','reset-admin'])
    args=parser.parse_args()
    {'init':init,'demo':demo,'backup':backup,'reset-admin':reset_admin}[args.command]()
