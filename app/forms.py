"""Form definitions and controlled write operations. Monetary values use cents."""
import sqlite3
from datetime import date
from .security import safe_text, valid_date, money, valid_username, valid_email, password_valid, password_hash
from .db import Database

PERM_CREATE = {
 'socios':'socios.crear','traspasos':'socios.crear','vehiculos':'unidades.editar','unidades':'unidades.editar','cambios':'unidades.editar',
 'reuniones':'actas.editar','actas':'actas.editar','convocatorias':'actas.editar','asistencia':'actas.editar',
 'ingresos':'finanzas.editar','deudas':'finanzas.editar','pagos':'finanzas.editar','marcaciones':'finanzas.editar',
 'multas':'multas.editar','vigilancia':'vigilancia.editar','usuarios':'usuarios.editar'
}

def field(name, title, type='text', required=True, options=None, placeholder=None):
    return dict(name=name,label=title,type=type,required=required,options=options or [],placeholder=placeholder or '')

def options(db, sql):
    return [(str(a),str(b)) for a,b in [list(x.values())[:2] for x in db.all(sql)]]

def spec(db,kind):
    socios=options(db,"SELECT id, name || CASE WHEN cedula IS NOT NULL AND cedula<>'' THEN ' · C.I: ' || cedula ELSE '' END FROM socios WHERE active=1 ORDER BY name")
    vehiculos=options(db,"SELECT id,plate FROM vehicles ORDER BY plate")
    unidades=options(db,"""SELECT u.id, u.code || ' · ' || COALESCE(s.name, 'Sin asignar') || CASE WHEN v.plate IS NOT NULL THEN ' (' || v.plate || ')' ELSE '' END FROM units u LEFT JOIN socios s ON s.id=u.socio_id LEFT JOIN vehicles v ON v.id=u.vehicle_id ORDER BY u.code""")
    transfer_units=options(db,"""SELECT u.id,u.code || ' · ' || s.name ||
        CASE WHEN v.plate IS NOT NULL THEN ' · ' || v.plate ELSE '' END
        FROM units u JOIN socios s ON s.id=u.socio_id
        LEFT JOIN vehicles v ON v.id=u.vehicle_id
        WHERE u.status='Activa' ORDER BY u.code""")
    meetings=options(db,"SELECT id,meeting_date || ' · ' || topic FROM meetings ORDER BY meeting_date DESC")
    debts=options(db,"SELECT d.id,s.name || ' · ' || d.concept || ' (pendiente)' FROM debts d JOIN socios s ON s.id=d.socio_id WHERE d.amount_cents>d.paid_cents ORDER BY d.id DESC")
    roles=options(db,'SELECT id,name FROM roles ORDER BY id')
    S={
     'socios':('Registrar socio',[field('name','Nombres y apellidos'),field('cedula','Cédula',required=False),field('phone','Teléfono',required=False),field('email','Correo electrónico','email',False),field('joined','Fecha de ingreso','date'),field('notes','Observaciones','textarea',False)]),
     'traspasos':('Registrar traspaso de unidad',[field('unit_id','Unidad que se traspasa','select',options=transfer_units),field('new_socio_id','Nuevo socio propietario','select',options=socios),field('transferred_at','Fecha del traspaso','date'),field('document_reference','Referencia del documento de compraventa',required=False),field('notes','Observaciones','textarea',False)]),
     'vehiculos':('Registrar vehículo',[field('plate','Placa'),field('brand','Marca',required=False),field('model','Modelo',required=False),field('year','Año','number',False),field('status','Estado','select',options=[('Activo','Activo'),('Mantenimiento','Mantenimiento'),('Inactivo','Inactivo')])]),
     'unidades':('Registrar unidad',[field('code','Código de unidad'),field('socio_id','Socio responsable','select',False,[('', 'Sin asignar')]+socios),field('vehicle_id','Vehículo','select',False,[('', 'Sin vehículo')]+vehiculos),field('status','Estado','select',options=[('Activa','Activa'),('Mantenimiento','Mantenimiento'),('Inactiva','Inactiva')])]),
     'cambios':('Registrar cambio de vehículo',[field('unit_id','Unidad','select',options=unidades),field('new_vehicle_id','Nuevo vehículo','select',options=vehiculos),field('reason','Motivo del cambio'),field('amount','Valor del cambio (S/)','money',False),field('changed_at','Fecha de cambio','date'),field('method','Forma de pago','select',options=[('Efectivo','Efectivo'),('Transferencia','Transferencia'),('Depósito','Depósito')])]),
     'reuniones':('Nueva reunión',[field('type','Tipo de reunión','select',options=[('Consejo de Administración','Consejo de Administración'),('Asamblea General','Asamblea General'),('Asamblea Extraordinaria','Asamblea Extraordinaria')]),field('topic','Tema'),field('meeting_date','Fecha','date'),field('meeting_time','Hora','time'),field('location','Lugar'),field('agenda','Orden del día','textarea',False)]),
     'actas':('Redactar acta',[field('meeting_id','Reunión','select',options=meetings),field('minutes','Contenido del acta','textarea'),field('minutes_state','Estado del acta','select',options=[('Borrador','Borrador'),('En revisión','En revisión'),('Aprobada','Aprobada')])]),
     'convocatorias':('Crear convocatoria',[field('meeting_id','Reunión','select',options=meetings),field('notice','Texto de la convocatoria','textarea')]),
     'asistencia':('Registrar asistencia',[field('meeting_id','Reunión','select',options=meetings),field('socio_id','Socio','select',options=socios),field('status','Asistencia','select',options=[('Asistió','Asistió'),('Faltó','Faltó'),('Justificó','Justificó')])]),
     'ingresos':('Registrar ingreso',[field('day','Fecha','date'),field('socio_id','Socio','select',False,[('', 'Ingreso de la compañía')]+socios),field('category','Tipo de ingreso','select',options=[('Aporte','Aporte'),('Cuota','Cuota'),('Servicio','Servicio'),('Cambio de vehículo','Cambio de vehículo'),('Otros','Otros')]),field('concept','Concepto'),field('amount','Monto (S/)','money'),field('method','Método de pago','select',options=[('Efectivo','Efectivo'),('Transferencia','Transferencia'),('Depósito','Depósito')])]),
     'deudas':('Registrar deuda',[field('socio_id','Socio','select',options=socios),field('concept','Concepto'),field('amount','Monto (S/)','money'),field('issued','Fecha de emisión','date'),field('due','Vencimiento','date',False)]),
     'pagos':('Registrar pago de deuda',[field('debt_id','Deuda pendiente','select',options=debts),field('amount','Monto abonado (S/)','money'),field('day','Fecha','date'),field('method','Medio de pago','select',options=[('Efectivo','Efectivo'),('Transferencia','Transferencia'),('Depósito','Depósito')])]),
     'marcaciones':('Marcación semanal',[field('socio_id','Socio','select',options=socios),field('week_start','Fecha de semana','date'),field('concept','Concepto de marcación'),field('amount','Importe (S/)','money',False),field('state','Estado','select',options=[('Marcado','Marcado'),('Pendiente','Pendiente')])]),
     'multas':('Registrar multa',[field('socio_id','Socio o conductor','select',options=socios),field('unit_id','Unidad','select',False,[('','Sin asignar')]+unidades),field('category','Categoría','select',options=[('Atraso','Atraso'),('Minutos','Minutos'),('Radio','Radio'),('Trabajo','Trabajo'),('Otros','Otros')]),field('reason','Motivo de la multa'),field('occurred_at','Fecha','date'),field('amount','Monto (S/)','money')]),
     'vigilancia':('Nuevo control de vigilancia',[field('day','Fecha','date'),field('socio_id','Socio','select',False,[('','Sin asignar')]+socios),field('unit_id','Unidad','select',False,[('','Sin unidad')]+unidades),field('category','Categoría','select',options=[('Control de trabajo','Control de trabajo'),('Atraso','Atraso'),('Radio','Radio'),('Ingreso','Ingreso'),('Otros','Otros')]),field('details','Descripción','textarea')]),
     'usuarios':('Registrar usuario',[field('full_name','Nombre completo'),field('username','Usuario'),field('email','Correo','email',False),field('role_id','Rol','select',options=roles),field('socio_id','Socio vinculado','select',False,[('','No vinculado')]+socios),field('password','Contraseña (mínimo 12 caracteres)','password')]),
    }
    if kind not in S: raise ValueError('Tipo de registro desconocido.')
    return {'kind':kind,'title':S[kind][0],'fields':S[kind][1]}

def save(db, kind, data, uid, existing_id=None, ip=None):
    if kind not in PERM_CREATE: raise ValueError('Acción desconocida.')
    data = dict(data)
    # Resolución automática por cédula o número de unidad si no se envió socio_id
    if kind in ('multas', 'ingresos', 'deudas', 'marcaciones', 'asistencia'):
        ced = str(data.get('lookup_cedula') or data.get('cedula') or '').strip()
        if ced and not data.get('socio_id'):
            s_row = db.one('SELECT id FROM socios WHERE cedula=? AND active=1', (ced,))
            if s_row: data['socio_id'] = str(s_row['id'])
        u_val = str(data.get('lookup_unit') or data.get('unit_code') or '').strip()
        if u_val:
            u_row = db.one("SELECT id, socio_id FROM units WHERE code=? OR id=?", (u_val, u_val))
            if u_row:
                if not data.get('unit_id'): data['unit_id'] = str(u_row['id'])
                if not data.get('socio_id') and u_row['socio_id']: data['socio_id'] = str(u_row['socio_id'])
        if data.get('socio_id') and not data.get('unit_id'):
            u_act = db.one("SELECT id FROM units WHERE socio_id=? AND status='Activa'", (data['socio_id'],))
            if u_act: data['unit_id'] = str(u_act['id'])
    s=spec(db,kind)
    v={}
    for f in s['fields']:
        n=f['name']; t=f['type']; val=str(data.get(n,'')).strip()
        if f['required'] and not val: raise ValueError(f'{f["label"]}: el campo es obligatorio.')
        if t=='select':
            accepted={o[0] for o in f['options']}
            if val not in accepted: raise ValueError(f'{f["label"]}: opción no válida.')
            v[n]=val
        elif t=='date': v[n]=valid_date(val).isoformat() if val else None
        elif t=='time':
            import datetime
            try: v[n]=datetime.time.fromisoformat(val).strftime('%H:%M')
            except ValueError: raise ValueError(f'{f["label"]}: hora inválida.')
        elif t=='money': v[n]=money(val or '0')
        elif t=='number':
            if val and (not val.isdigit() or not 1900<=int(val)<=2150): raise ValueError('Año fuera de rango.')
            v[n]=int(val) if val else None
        elif t=='textarea': v[n]=safe_text(val,f['label'],5000,f['required'])
        else: v[n]=safe_text(val,f['label'],180,f['required'])
    def nullable(name):return int(v[name]) if v.get(name) else None
    with db.connection() as con:
        period=Database.ensure_period(con,date.today())
        if kind not in ('socios','traspasos','vehiculos','unidades','reuniones','actas','convocatorias','asistencia','usuarios') and period['closed_at']:
            raise ValueError('No se puede registrar: el periodo está cerrado.')
        financial_date={'cambios':'changed_at','ingresos':'day','deudas':'issued','pagos':'day',
                        'marcaciones':'week_start','multas':'occurred_at','vigilancia':'day'}.get(kind)
        if financial_date and not (period['starts']<=v[financial_date]<=period['ends']):
            raise ValueError(f'La fecha debe estar dentro del periodo activo ({period["starts"]} a {period["ends"]}).')
        if existing_id is not None and kind not in ('socios','vehiculos','unidades','reuniones'):
            raise ValueError('Este tipo de registro se corrige mediante una nueva operación, no editando su historial.')
        if kind=='socios':
            if existing_id:
                con.execute('UPDATE socios SET name=?,cedula=?,phone=?,email=?,joined=?,notes=? WHERE id=?',(v['name'],v['cedula'] or None,v['phone'],v['email'] or None,v['joined'],v['notes'],existing_id)); rid=existing_id
            else:
                cur=con.execute('INSERT INTO socios(name,cedula,phone,email,joined,notes) VALUES(?,?,?,?,?,?)',(v['name'],v['cedula'] or None,v['phone'],v['email'] or None,v['joined'],v['notes']));rid=cur.lastrowid
        elif kind=='vehiculos':
            if existing_id:
                con.execute('UPDATE vehicles SET plate=?,brand=?,model=?,year=?,status=? WHERE id=?',(v['plate'].upper(),v['brand'],v['model'],v['year'],v['status'],existing_id));rid=existing_id
            else:
                rid=con.execute('INSERT INTO vehicles(plate,brand,model,year,status) VALUES(?,?,?,?,?)',(v['plate'].upper(),v['brand'],v['model'],v['year'],v['status'])).lastrowid
        elif kind=='unidades':
            if existing_id:
                previous=con.execute('SELECT socio_id FROM units WHERE id=?',(existing_id,)).fetchone()
                if previous and previous['socio_id'] is not None and previous['socio_id']!=nullable('socio_id'):
                    raise ValueError('Para cambiar al propietario de una unidad, registre un traspaso desde Socios > Traspasos.')
                if v['status']=='Activa' and nullable('socio_id') is not None and con.execute(
                    "SELECT 1 FROM units WHERE socio_id=? AND status='Activa' AND id<>?",
                    (nullable('socio_id'),existing_id)).fetchone():
                    raise ValueError('El socio ya tiene otra unidad activa.')
                con.execute('UPDATE units SET code=?,socio_id=?,vehicle_id=?,status=? WHERE id=?',(v['code'],nullable('socio_id'),nullable('vehicle_id'),v['status'],existing_id));rid=existing_id
            else:
                if v['status']=='Activa' and nullable('socio_id') is not None and con.execute(
                    "SELECT 1 FROM units WHERE socio_id=? AND status='Activa'",
                    (nullable('socio_id'),)).fetchone():
                    raise ValueError('El socio ya tiene otra unidad activa.')
                rid=con.execute('INSERT INTO units(code,socio_id,vehicle_id,status) VALUES(?,?,?,?)',(v['code'],nullable('socio_id'),nullable('vehicle_id'),v['status'])).lastrowid
        elif kind=='traspasos':
            unit=con.execute("""SELECT u.id,u.code,u.socio_id,u.status,s.name AS seller
                FROM units u JOIN socios s ON s.id=u.socio_id WHERE u.id=?""",(int(v['unit_id']),)).fetchone()
            buyer=con.execute('SELECT id,name FROM socios WHERE id=? AND active=1',(int(v['new_socio_id']),)).fetchone()
            if not unit or unit['status']!='Activa':
                raise ValueError('La unidad seleccionada ya no está disponible para traspaso.')
            if not buyer:
                raise ValueError('El nuevo socio debe estar activo.')
            if unit['socio_id']==buyer['id']:
                raise ValueError('El nuevo propietario debe ser distinto del propietario actual.')
            if con.execute("SELECT 1 FROM units WHERE socio_id=? AND status='Activa' AND id<>?",
                           (buyer['id'],unit['id'])).fetchone():
                raise ValueError('El nuevo socio ya tiene una unidad activa.')
            rid=con.execute("""INSERT INTO ownership_transfers
                (unit_id,from_socio_id,to_socio_id,transferred_at,includes_shares,includes_rights,
                 document_reference,notes,created_by)
                VALUES(?,?,?,?,1,1,?,?,?)""",
                (unit['id'],unit['socio_id'],buyer['id'],v['transferred_at'],
                 v['document_reference'],v['notes'],uid)).lastrowid
            con.execute('UPDATE units SET socio_id=? WHERE id=?',(buyer['id'],unit['id']))
            con.execute('UPDATE socios SET active=0 WHERE id=?',(unit['socio_id'],))
            Database.audit(con,uid,'Traspasar','traspasos',rid,
                           f"Unidad {unit['code']}: {unit['seller']} → {buyer['name']} (bus, acciones y derechos)", ip=ip)
            return rid
        elif kind=='cambios':
            prev=con.execute('SELECT vehicle_id FROM units WHERE id=?',(v['unit_id'],)).fetchone()
            if not prev: raise ValueError('La unidad indicada no existe.')
            new=nullable('new_vehicle_id')
            if prev['vehicle_id']==new: raise ValueError('El nuevo vehículo debe ser distinto al actual.')
            rid=con.execute('INSERT INTO vehicle_changes(unit_id,old_vehicle_id,new_vehicle_id,reason,amount_cents,changed_at,period_id,created_by) VALUES(?,?,?,?,?,?,?,?)',(int(v['unit_id']),prev['vehicle_id'],new,v['reason'],v['amount'],v['changed_at'],period['id'],uid)).lastrowid
            con.execute('UPDATE units SET vehicle_id=? WHERE id=?',(new,int(v['unit_id'])))
            if v['amount']:
                unit=con.execute('SELECT code,socio_id FROM units WHERE id=?',(int(v['unit_id']),)).fetchone()
                con.execute('INSERT INTO incomes(period_id,socio_id,category,concept,amount_cents,method,day,created_by) VALUES(?,?,?,?,?,?,?,?)',
                            (period['id'],unit['socio_id'],'Cambio de vehículo',
                             'Cambio de vehículo · '+unit['code'],v['amount'],v['method'],v['changed_at'],uid))
        elif kind=='reuniones':
            if existing_id:
                con.execute('UPDATE meetings SET type=?,topic=?,meeting_date=?,meeting_time=?,location=?,agenda=? WHERE id=?',(v['type'],v['topic'],v['meeting_date'],v['meeting_time'],v['location'],v['agenda'],existing_id));rid=existing_id
            else:
                rid=con.execute('INSERT INTO meetings(type,topic,meeting_date,meeting_time,location,agenda,created_by) VALUES(?,?,?,?,?,?,?)',(v['type'],v['topic'],v['meeting_date'],v['meeting_time'],v['location'],v['agenda'],uid)).lastrowid
        elif kind=='actas':
            rid=int(v['meeting_id'])
            con.execute('UPDATE meetings SET minutes=?,minutes_state=? WHERE id=?',(v['minutes'],v['minutes_state'],rid))
        elif kind=='convocatorias':
            rid=int(v['meeting_id'])
            con.execute("UPDATE meetings SET notice=?,notice_sent_at=CURRENT_TIMESTAMP WHERE id=?",(v['notice'],rid))
        elif kind=='asistencia':
            rid=int(v['meeting_id'])
            con.execute('INSERT INTO attendance(meeting_id,socio_id,status) VALUES(?,?,?) ON CONFLICT(meeting_id,socio_id) DO UPDATE SET status=excluded.status',(rid,int(v['socio_id']),v['status']))
        elif kind=='ingresos':
            if not v['amount']: raise ValueError('El monto debe ser mayor que cero.')
            rid=con.execute('INSERT INTO incomes(period_id,socio_id,category,concept,amount_cents,method,day,created_by) VALUES(?,?,?,?,?,?,?,?)',(period['id'],nullable('socio_id'),v['category'],v['concept'],v['amount'],v['method'],v['day'],uid)).lastrowid
        elif kind=='deudas':
            if not v['amount']: raise ValueError('El monto debe ser mayor que cero.')
            rid=con.execute('INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued,due,created_by) VALUES(?,?,?,?,?,?,?)',(period['id'],nullable('socio_id'),v['concept'],v['amount'],v['issued'],v['due'],uid)).lastrowid
        elif kind=='pagos':
            if not v['amount']: raise ValueError('El pago debe ser mayor que cero.')
            debt=con.execute('SELECT * FROM debts WHERE id=?',(int(v['debt_id']),)).fetchone()
            if not debt or v['amount']>debt['amount_cents']-debt['paid_cents']:
                raise ValueError('El abono supera el saldo pendiente de la deuda.')
            rid=con.execute('INSERT INTO payments(period_id,debt_id,socio_id,amount_cents,method,day,created_by) VALUES(?,?,?,?,?,?,?)',(period['id'],debt['id'],debt['socio_id'],v['amount'],v['method'],v['day'],uid)).lastrowid
            con.execute('UPDATE debts SET paid_cents=paid_cents+? WHERE id=?',(v['amount'],debt['id']))
            if debt['fine_id'] and debt['paid_cents']+v['amount']==debt['amount_cents']:
                con.execute("UPDATE fines SET status='Pagada' WHERE id=?",(debt['fine_id'],))
        elif kind=='marcaciones':
            rid=con.execute('INSERT INTO weekly_marks(period_id,socio_id,week_start,concept,amount_cents,state,created_by) VALUES(?,?,?,?,?,?,?)',(period['id'],nullable('socio_id'),v['week_start'],v['concept'],v['amount'],v['state'],uid)).lastrowid
        elif kind=='multas':
            if not v['amount']: raise ValueError('La multa debe tener un monto mayor que cero.')
            rid=con.execute('INSERT INTO fines(period_id,socio_id,unit_id,category,reason,occurred_at,amount_cents,created_by) VALUES(?,?,?,?,?,?,?,?)',(period['id'],nullable('socio_id'),nullable('unit_id'),v['category'],v['reason'],v['occurred_at'],v['amount'],uid)).lastrowid
            con.execute('INSERT INTO debts(period_id,socio_id,concept,amount_cents,issued,fine_id,created_by) VALUES(?,?,?,?,?,?,?)',(period['id'],nullable('socio_id'),'Multa: '+v['reason'],v['amount'],v['occurred_at'],rid,uid))
        elif kind=='vigilancia':
            rid=con.execute('INSERT INTO vigilance(period_id,socio_id,unit_id,category,details,day,created_by) VALUES(?,?,?,?,?,?,?)',(period['id'],nullable('socio_id'),nullable('unit_id'),v['category'],v['details'],v['day'],uid)).lastrowid
        elif kind=='usuarios':
            v['username']=valid_username(v['username'])
            v['email']=valid_email(v['email'])
            if not password_valid(v['password']): raise ValueError('La contraseña debe tener entre 12 y 128 caracteres.')
            if v['role_id']==str(con.execute("SELECT id FROM roles WHERE name='Socio'").fetchone()['id']) and not v['socio_id']:
                raise ValueError('Los usuarios con rol Socio deben estar vinculados a un socio.')
            rid=con.execute('INSERT INTO users(username,full_name,email,password_hash,role_id,socio_id) VALUES(?,?,?,?,?,?)',(v['username'],v['full_name'],v['email'] or None,password_hash(v['password']),int(v['role_id']),nullable('socio_id'))).lastrowid
        action = 'Editar' if existing_id else 'Crear'
        summary = ''
        if kind == 'socios':
            summary = f"Socio: {v.get('name')} (Cédula: {v.get('cedula') or 'S/C'})"
        elif kind == 'vehiculos':
            summary = f"Vehículo placa: {v.get('plate')} ({v.get('brand','')} {v.get('model','')})"
        elif kind == 'unidades':
            summary = f"Unidad: {v.get('code')} - Estado: {v.get('status')}"
        elif kind == 'cambios':
            summary = f"Cambio de vehículo para unidad ID {v.get('unit_id')} ({v.get('reason','')})"
        elif kind == 'reuniones':
            summary = f"Reunión: {v.get('type')} - {v.get('topic')} ({v.get('meeting_date')})"
        elif kind == 'actas':
            summary = f"Acta de reunión ID {rid} - Estado: {v.get('minutes_state')}"
        elif kind == 'convocatorias':
            summary = f"Convocatoria de reunión ID {rid}"
        elif kind == 'asistencia':
            summary = f"Asistencia individual registrada para reunión ID {rid}"
        elif kind == 'ingresos':
            amt_val = v.get('amount', 0)
            amt_str = f"{amt_val/100:.2f} S/" if isinstance(amt_val, (int, float)) else str(amt_val)
            summary = f"Ingreso de {amt_str} - {v.get('concept')} ({v.get('category')})"
        elif kind == 'deudas':
            amt_val = v.get('amount', 0)
            amt_str = f"{amt_val/100:.2f} S/" if isinstance(amt_val, (int, float)) else str(amt_val)
            summary = f"Deuda de {amt_str} - {v.get('concept')}"
        elif kind == 'pagos':
            amt_val = v.get('amount', 0)
            amt_str = f"{amt_val/100:.2f} S/" if isinstance(amt_val, (int, float)) else str(amt_val)
            summary = f"Abono de {amt_str} a deuda ID {v.get('debt_id')} ({v.get('method')})"
        elif kind == 'marcaciones':
            summary = f"Marcación semanal {v.get('week_start')} - {v.get('concept')} ({v.get('state')})"
        elif kind == 'multas':
            amt_val = v.get('amount', 0)
            amt_str = f"{amt_val/100:.2f} S/" if isinstance(amt_val, (int, float)) else str(amt_val)
            summary = f"Multa de {amt_str} - {v.get('reason')} ({v.get('category')})"
        elif kind == 'vigilancia':
            summary = f"Control vigilancia: {v.get('category')} - {str(v.get('details',''))[:60]}"
        elif kind == 'usuarios':
            summary = f"Usuario: {v.get('username')} ({v.get('full_name')})"

        Database.audit(con, uid, action, kind, rid, summary, ip=ip)
        return rid
