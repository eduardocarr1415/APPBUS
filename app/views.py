"""Presentation queries for separated, navigable tabs."""
from datetime import date
from .reports import fmt

NAV = [
 ('dashboard','/','▦','Dashboard',''),
 ('socios','/socios','♙','Socios','socios.ver'),
 ('actas','/actas','▤','Actas y reuniones','actas.ver'),
 ('finanzas','/finanzas','▥','Ingresos económicos','finanzas.ver'),
 ('multas','/multas','⚒','Multas','multas.ver'),
 ('unidades','/unidades','▣','Unidades y vehículos','unidades.ver'),
 ('reportes','/reportes','▥','Reportes','reportes.ver'),
 ('usuarios','/usuarios','♙','Usuarios y permisos','usuarios.ver'),
 ('auditoria','/auditoria','⏱','Historial del sistema','auditoria.ver'),
 ('configuracion','/configuracion','⚙','Configurar página','configuracion.ver'),
]
TABS={
 'socios':[('listado','Socios'),('unidades','Unidades asignadas'),('traspasos','Historial de traspasos')],
 'actas':[('actas','Actas'),('reuniones','Reuniones'),('convocatorias','Convocatorias'),('asistencia','Asistencia')],
 'finanzas':[('resumen','Resumen'),('ingresos','Ingresos'),('pagos','Pagos'),('deudas','Deudas'),('marcaciones','Marcación semanal'),('historial','Historial')],
 'multas':[('multas','Multas'),('pendientes','Pendientes'),('pagadas','Pagadas')],
 'unidades':[('unidades','Unidades'),('vehiculos','Vehículos'),('cambios','Cambios de vehículo')],
 'reportes':[('resumen','Resumen'),('financieros','Finanzas y gestión'),('multas','Multas'),('asistencia','Asistencia'),('unidades','Unidades'),('cierre','Cierre anual de multas'),('historial','Historial de multas')],
 'usuarios':[('usuarios','Usuarios'),('roles','Roles'),('permisos','Permisos'),('auditoria','Auditoría')],
 'auditoria':[('todos','Todo el historial'),('logins','Inicios y accesos'),('operaciones','Operaciones'),('seguridad','Seguridad')],
}
TITLES={'socios':'Socios','actas':'Actas y reuniones','finanzas':'Ingresos económicos','multas':'Multas','unidades':'Unidades y vehículos','reportes':'Reportes','usuarios':'Usuarios y permisos','auditoria':'Historial del sistema'}
SUBTITLES={'socios':'Registro y administración de los socios de la compañía.',
'actas':'Gestión de actas, reuniones, convocatorias y asistencia.',
'finanzas':'Control de ingresos, pagos y deudas de la compañía.',
'multas':'Registro, cobro y seguimiento de multas.',
'unidades':'Control de vehículos, asignaciones y cambios de unidad.',
'reportes':'Informes organizados por tema, con periodos y cierres de multas independientes.',
'usuarios':'Gestión de usuarios, roles, permisos y auditoría.',
'auditoria':'Registro integral de auditoría, accesos al sistema y operaciones de usuarios.'}

def card(label, value, icon='▦', color='blue'):
    return {'label':label,'value':value,'icon':icon,'color':color}

def table(headers, rows, keys=None):
    return {'headers':headers,'rows':rows,'keys':keys or headers}

def modules(db, key, tab, role_name='', socio_id=None):
    """Return safe structured data; HTML is escaped by Jinja templates."""
    p=db.current_period(); pid=p['id']
    result={'cards':[],'headers':[],'rows':[],'section':'','new_kind':None,'new_label':'Nuevo registro','side_title':None,'side_rows':[]}
    R=result
    def settable(title, headers, sql, args=(), transform=None):
        rr=db.all(sql,args)
        R.update(section=title,headers=headers,rows=[transform(x) if transform else list(x.values()) for x in rr])
    # Adjacency to financial data is never global for Socio, only own records.
    own = role_name == 'Socio'
    if key == 'socios':
        R['cards']=[card('Socios activos',db.one('SELECT COUNT(*) n FROM socios WHERE active=1')['n'],'♙'),card('Unidades registradas',db.one('SELECT COUNT(*) n FROM units')['n'],'▣')]
        if tab=='unidades':
            settable('Unidades de los socios',['Unidad','Socio','Placa','Estado'],'''SELECT u.code,COALESCE(s.name,'Sin asignar'),COALESCE(v.plate,'Sin vehículo'),u.status FROM units u LEFT JOIN socios s ON s.id=u.socio_id LEFT JOIN vehicles v ON v.id=u.vehicle_id'''+(' WHERE u.socio_id=?' if own else '')+' ORDER BY u.code',(socio_id,) if own else ())
        elif tab=='traspasos':
            settable('Historial de traspasos',['ID','Fecha','Unidad','Placa','Socio vendedor','Nuevo socio','Transferencia'],'''SELECT t.id,t.transferred_at,u.code,COALESCE(v.plate,'Sin vehículo'),seller.name AS seller_name,buyer.name AS buyer_name,
                CASE WHEN t.includes_shares=1 AND t.includes_rights=1 THEN 'Bus, acciones y derechos' ELSE 'Bus' END
                FROM ownership_transfers t JOIN units u ON u.id=t.unit_id
                LEFT JOIN vehicles v ON v.id=u.vehicle_id
                JOIN socios seller ON seller.id=t.from_socio_id
                JOIN socios buyer ON buyer.id=t.to_socio_id'''+(' WHERE t.from_socio_id=? OR t.to_socio_id=?' if own else '')+' ORDER BY t.transferred_at DESC,t.id DESC',(socio_id,socio_id) if own else ())
            R.update(new_kind='traspasos',new_label='Registrar traspaso',
                     side_rows=[('Regla','Una sola unidad activa por socio'),('Registro','Cada cambio conserva vendedor, comprador y fecha'),('Alcance','El traspaso incluye bus, acciones y derechos')])
        else:
            settable('Socios registrados',['ID','Socio','Cédula','Teléfono','Estado'],'''SELECT id,name,COALESCE(cedula,''),COALESCE(phone,''),CASE WHEN active=1 THEN 'Activo' ELSE 'Inactivo' END FROM socios ORDER BY name''')
            R.update(new_kind='socios',new_label='Registrar socio')
    elif key=='actas':
        R['cards']=[card('Reuniones',db.one('SELECT COUNT(*) n FROM meetings')['n'],'▤'),card('Actas aprobadas',db.one("SELECT COUNT(*) n FROM meetings WHERE minutes_state='Aprobada'")['n'],'✓','green'),card('Convocatorias publicadas',db.one('SELECT COUNT(*) n FROM meetings WHERE notice_sent_at IS NOT NULL')['n'],'◉')]
        if tab=='actas':
            settable('Actas de reuniones',['ID','Fecha','Tipo','Tema','Estado'],'''SELECT id,meeting_date,type,topic,minutes_state FROM meetings WHERE minutes<>'' ORDER BY meeting_date DESC''')
            R.update(new_kind='actas',new_label='Redactar acta')
        elif tab=='reuniones':
            settable('Reuniones programadas',['ID','Fecha','Hora','Tipo','Tema','Estado'],'''SELECT id,meeting_date,meeting_time,type,topic,status FROM meetings ORDER BY meeting_date DESC''')
            R.update(new_kind='reuniones',new_label='Nueva reunión')
        elif tab=='convocatorias':
            R.update(section='Convocatorias a reuniones',new_kind=None)
        else:
            R.update(section='Control de asistencia',new_kind=None)
    elif key=='finanzas':
        own_filter=' AND i.socio_id=?' if own else ''
        own_args=(pid,socio_id) if own else (pid,)
        total_income=db.one('SELECT COALESCE(SUM(amount_cents),0) n FROM incomes WHERE period_id=?'+(' AND socio_id=?' if own else ''),own_args)['n']
        payargs=(pid,socio_id) if own else (pid,)
        total_pay=db.one('SELECT COALESCE(SUM(amount_cents),0) n FROM payments WHERE period_id=?'+(' AND socio_id=?' if own else ''),payargs)['n']
        pending=db.one('SELECT COALESCE(SUM(amount_cents-paid_cents),0) n FROM debts WHERE amount_cents>paid_cents'+(' AND socio_id=?' if own else ''),(socio_id,) if own else ())['n']
        R['cards']=[card('Ingresos del periodo',fmt(total_income),'▥','green'),card('Pagos recibidos',fmt(total_pay),'▣','blue'),card('Deuda pendiente total',fmt(pending),'◇','red')]
        if tab in ('ingresos','historial','resumen'):
            settable('Ingresos registrados',['ID','Fecha','Concepto','Socio','Valor','Método'],'''SELECT i.id,i.day,i.concept,COALESCE(s.name,'Compañía'),i.amount_cents,i.method FROM incomes i LEFT JOIN socios s ON s.id=i.socio_id WHERE i.period_id=?'''+own_filter+' ORDER BY i.day DESC,i.id DESC LIMIT 150',own_args,lambda x:[x['id'],x['day'],x['concept'],x["COALESCE(s.name,'Compañía')"],fmt(x['amount_cents']),x['method']])
            R.update(new_kind='ingresos',new_label='Registrar ingreso')
        elif tab=='pagos':
            settable('Pagos de deudas',['ID','Fecha','Socio','Deuda','Abono','Método'],'''SELECT p.id,p.day,s.name,d.concept,p.amount_cents,p.method FROM payments p JOIN socios s ON s.id=p.socio_id JOIN debts d ON d.id=p.debt_id WHERE p.period_id=?'''+(' AND p.socio_id=?' if own else '')+' ORDER BY p.id DESC LIMIT 150',payargs,lambda x:[x['id'],x['day'],x['name'],x['concept'],fmt(x['amount_cents']),x['method']])
            R.update(new_kind='pagos',new_label='Registrar pago')
        elif tab=='deudas':
            settable('Deudas y saldos pendientes',['ID','Socio','Concepto','Total','Abonado','Pendiente'],'''SELECT d.id,s.name,d.concept,d.amount_cents,d.paid_cents,(d.amount_cents-d.paid_cents) remaining FROM debts d JOIN socios s ON s.id=d.socio_id WHERE 1=1'''+(' AND d.socio_id=?' if own else '')+' ORDER BY d.id DESC LIMIT 150',(socio_id,) if own else (),lambda x:[x['id'],x['name'],x['concept'],fmt(x['amount_cents']),fmt(x['paid_cents']),fmt(x['remaining'])])
            R.update(new_kind='deudas',new_label='Registrar deuda')
        elif tab=='marcaciones':
            settable('Marcación semanal',['ID','Socio','Semana','Concepto','Valor','Estado'],'''SELECT w.id,s.name,w.week_start,w.concept,w.amount_cents,w.state FROM weekly_marks w JOIN socios s ON s.id=w.socio_id WHERE w.period_id=?'''+(' AND w.socio_id=?' if own else '')+' ORDER BY w.week_start DESC',own_args,lambda x:[x['id'],x['name'],x['week_start'],x['concept'],fmt(x['amount_cents']),x['state']])
            R.update(new_kind='marcaciones',new_label='Nueva marcación')
        R['side_title']='Periodo activo'
        R['side_rows']=[('Desde',p['starts']),('Hasta',p['ends']),('Estado','Cerrado' if p['closed_at'] else 'Abierto'),('Cobrado',fmt(total_income+total_pay))]
    elif key=='multas':
        q=' AND f.socio_id=?' if own else ''
        args=(socio_id,) if own else ()
        n=db.one('SELECT COUNT(*) n FROM fines f WHERE 1=1'+q,args)['n']
        pe=db.one("SELECT COUNT(*) n FROM fines f WHERE status='Pendiente'"+q,args)['n']
        pa=db.one("SELECT COUNT(*) n FROM fines f WHERE status='Pagada'"+q,args)['n']
        R['cards']=[card('Multas registradas',n,'⚒'),card('Pendientes',pe,'!','orange' if pe else 'green'),card('Pagadas',pa,'✓','green')]
        if tab=='pagadas':
            settable('Listado de multas pagadas',['ID','Fecha','Socio','Cédula','Unidad','Motivo','Monto','Estado'],'''SELECT f.id,f.occurred_at,s.name,COALESCE(s.cedula,'—'),COALESCE(u.code,'Sin unidad'),f.reason,f.amount_cents,f.status FROM fines f JOIN socios s ON s.id=f.socio_id LEFT JOIN units u ON u.id=f.unit_id WHERE f.status="Pagada" '''+q+' ORDER BY f.id DESC LIMIT 150',args,lambda x:[x['id'],x['occurred_at'],x['name'],x["COALESCE(s.cedula,'—')"],x["COALESCE(u.code,'Sin unidad')"],x['reason'],fmt(x['amount_cents']),x['status']])
        elif tab=='pendientes':
            settable('Listado de multas pendientes',['ID','Fecha','Socio','Cédula','Unidad','Motivo','Monto','Estado'],'''SELECT f.id,f.occurred_at,s.name,COALESCE(s.cedula,'—'),COALESCE(u.code,'Sin unidad'),f.reason,f.amount_cents,f.status FROM fines f JOIN socios s ON s.id=f.socio_id LEFT JOIN units u ON u.id=f.unit_id WHERE f.status="Pendiente" '''+q+' ORDER BY f.id DESC LIMIT 150',args,lambda x:[x['id'],x['occurred_at'],x['name'],x["COALESCE(s.cedula,'—')"],x["COALESCE(u.code,'Sin unidad')"],x['reason'],fmt(x['amount_cents']),x['status']])
            R.update(new_kind='multas',new_label='Registrar multa')
        else:
            settable('Listado de multas',['ID','Fecha','Socio','Cédula','Unidad','Motivo','Monto','Estado'],'''SELECT f.id,f.occurred_at,s.name,COALESCE(s.cedula,'—'),COALESCE(u.code,'Sin unidad'),f.reason,f.amount_cents,f.status FROM fines f JOIN socios s ON s.id=f.socio_id LEFT JOIN units u ON u.id=f.unit_id WHERE 1=1'''+q+' ORDER BY f.id DESC LIMIT 150',args,lambda x:[x['id'],x['occurred_at'],x['name'],x["COALESCE(s.cedula,'—')"],x["COALESCE(u.code,'Sin unidad')"],x['reason'],fmt(x['amount_cents']),x['status']])
            R.update(new_kind='multas',new_label='Registrar multa')
    elif key=='unidades':
        R['cards']=[card('Unidades',db.one('SELECT COUNT(*) n FROM units')['n'],'▣'),card('Vehículos',db.one('SELECT COUNT(*) n FROM vehicles')['n'],'▣'),card('Cambios del periodo',db.one('SELECT COUNT(*) n FROM vehicle_changes WHERE period_id=?',(pid,))['n'],'⇄')]
        if tab=='vehiculos':
            settable('Vehículos registrados',['ID','Placa','Marca','Modelo','Año','Estado'],'''SELECT v.id,v.plate,COALESCE(v.brand,''),COALESCE(v.model,''),COALESCE(v.year,''),v.status FROM vehicles v'''+(' JOIN units u ON u.vehicle_id=v.id WHERE u.socio_id=?' if own else '')+' ORDER BY v.plate',(socio_id,) if own else ())
            R.update(new_kind='vehiculos',new_label='Registrar vehículo')
        elif tab=='cambios':
            settable('Historial de cambios',['ID','Fecha','Unidad','Placa anterior','Nueva placa','Costo'],'''SELECT c.id,c.changed_at,u.code,COALESCE(v1.plate,'Sin vehículo'),v2.plate,c.amount_cents FROM vehicle_changes c JOIN units u ON u.id=c.unit_id LEFT JOIN vehicles v1 ON v1.id=c.old_vehicle_id JOIN vehicles v2 ON v2.id=c.new_vehicle_id'''+(' WHERE u.socio_id=?' if own else '')+' ORDER BY c.id DESC',(socio_id,) if own else (),transform=lambda x:[x['id'],x['changed_at'],x['code'],x["COALESCE(v1.plate,'Sin vehículo')"],x['plate'],fmt(x['amount_cents'])])
            R.update(new_kind='cambios',new_label='Registrar cambio')
        else:
            settable('Unidades registradas',['ID','Unidad','Socio','Placa','Estado'],'''SELECT u.id,u.code,COALESCE(s.name,'Sin asignar'),COALESCE(v.plate,'Sin vehículo'),u.status FROM units u LEFT JOIN socios s ON s.id=u.socio_id LEFT JOIN vehicles v ON v.id=u.vehicle_id'''+(' WHERE u.socio_id=?' if own else '')+' ORDER BY u.code',(socio_id,) if own else ())
            R.update(new_kind='unidades',new_label='Nueva unidad')
    elif key=='reportes':
        cycle=db.current_fine_cycle()
        active_fines=db.one('''SELECT COUNT(*) AS count,COALESCE(SUM(amount_cents),0) AS total,
            COALESCE(SUM(CASE WHEN status='Pendiente' THEN amount_cents ELSE 0 END),0) AS pending
            FROM fines WHERE fine_cycle_id=?''',(cycle['id'],))
        today=date.today().isoformat()
        R.update(fine_cycle=cycle,active_fines=active_fines,today=today,
                 can_close_cycle=cycle['starts']<=today,current_month=date.today().strftime('%Y-%m'))
        if tab=='resumen':
            R['cards']=[card('Periodo económico',p['label'],'▦'),
                        card('Multas acumuladas',active_fines['count'],'⚒'),
                        card('Monto de multas',fmt(active_fines['total']),'▤')]
            R.update(section='Resumen del periodo',
                     section_description='Indicadores consolidados. Los detalles de cada tema están en su pestaña para evitar repetir registros.')
        elif tab=='financieros':
            R.update(section='Finanzas y gestión mensual',
                     section_description='El detalle financiero reúne ingresos y pagos; el informe gerencial resume los movimientos del mes sin volver a registrarlos.')
        elif tab=='multas':
            R['cards']=[card('Multas del ciclo',active_fines['count'],'⚒'),
                        card('Monto registrado',fmt(active_fines['total']),'▤'),
                        card('Pendiente',fmt(active_fines['pending']),'◇','red')]
            settable('Multas del ciclo actual',['Fecha','Socio','Motivo','Monto','Estado'],'''SELECT f.occurred_at,s.name,f.reason,f.amount_cents,f.status
                FROM fines f JOIN socios s ON s.id=f.socio_id WHERE f.fine_cycle_id=? ORDER BY f.occurred_at DESC,f.id DESC''',
                (cycle['id'],),lambda x:[x['occurred_at'],x['name'],x['reason'],fmt(x['amount_cents']),x['status']])
        elif tab in ('asistencia','unidades'):
            R.update(section='Informe de asistencia' if tab=='asistencia' else 'Inventario de unidades',
                     section_description='Descargue el informe correspondiente. Esta sección ofrece el informe, sin duplicar aquí el detalle que ya existe en su módulo.')
        elif tab=='cierre':
            R['cards']=[card('Ciclo de multas',cycle['label'],'⚒'),
                        card('Multas acumuladas',active_fines['count'],'▤'),
                        card('Monto acumulado',fmt(active_fines['total']),'◇')]
            R.update(section='Cierre del ciclo de multas',
                     section_description='El cierre conserva el historial y los totales. No elimina multas ni cierra ingresos, pagos o deudas.')
        elif tab=='historial':
            R.update(section='Ciclos cerrados de multas',
                     fine_history=db.all('''SELECT c.id,c.label,c.starts,c.ends,c.closed_at,c.snapshot,
                         COUNT(f.id) AS fine_count,COALESCE(SUM(f.amount_cents),0) AS fine_total
                         FROM fine_cycles c LEFT JOIN fines f ON f.fine_cycle_id=c.id
                         WHERE c.closed_at IS NOT NULL GROUP BY c.id ORDER BY c.ends DESC,c.id DESC'''))
    elif key=='usuarios':
        R['cards']=[card('Usuarios totales',db.one('SELECT COUNT(*) n FROM users')['n'],'♙'),card('Usuarios activos',db.one('SELECT COUNT(*) n FROM users WHERE active=1')['n'],'✓','green'),card('Roles definidos',db.one('SELECT COUNT(*) n FROM roles')['n'],'▧')]
        if tab=='roles':
            settable('Roles existentes',['ID','Rol','Usuarios'],'''SELECT r.id,r.name,COUNT(u.id) FROM roles r LEFT JOIN users u ON u.role_id=r.id GROUP BY r.id ORDER BY r.id''')
        elif tab=='auditoria':
            settable('Auditoría reciente',['ID','Fecha y hora','IP del dispositivo','Usuario','Rol','Acción','Módulo','Detalle'],'''SELECT a.id,a.created_at,COALESCE(a.ip_address,'127.0.0.1'),COALESCE(u.username,'Sistema / Anónimo'),COALESCE(r.name,'—'),a.action,a.entity,COALESCE(a.summary,'') FROM audit a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN roles r ON r.id=u.role_id ORDER BY a.id DESC LIMIT 150''')
        elif tab=='permisos':
            R.update(section='Permisos por rol',role_rows=db.all('SELECT * FROM roles ORDER BY id'))
        else:
            settable('Usuarios del sistema',['ID','Nombre','Usuario','Rol','Estado'],'''SELECT u.id,u.full_name,u.username,r.name,CASE WHEN u.active=1 THEN 'Activo' ELSE 'Inactivo' END FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id DESC''')
            R.update(new_kind='usuarios',new_label='Nuevo usuario')
    elif key=='auditoria':
        total_ev = db.one('SELECT COUNT(*) n FROM audit')['n']
        logins_ev = db.one("SELECT COUNT(*) n FROM audit WHERE entity='autenticacion' AND action IN ('Ingresar','Inicio de sesión')")['n']
        fails_ev = db.one("SELECT COUNT(*) n FROM audit WHERE action IN ('Intento fallido','Bloqueo temporal')")['n']
        last_ev = db.one('SELECT created_at FROM audit ORDER BY id DESC LIMIT 1')
        last_time = last_ev['created_at'][11:19] if last_ev and len(last_ev['created_at'])>=19 else (last_ev['created_at'] if last_ev else '—')
        R['cards'] = [
            card('Total eventos', total_ev, '⏱', 'blue'),
            card('Inicios de sesión', logins_ev, '✓', 'green'),
            card('Alertas de acceso', fails_ev, '!', 'red' if fails_ev else 'purple'),
            card('Último evento', last_time, '▦', 'blue'),
        ]
        if tab == 'logins':
            settable('Historial de accesos e inicios de sesión',
                     ['ID', 'Fecha y hora', 'IP del dispositivo', 'Usuario', 'Rol', 'Evento', 'Detalle'],
                     '''SELECT a.id, a.created_at, COALESCE(a.ip_address, '127.0.0.1'),
                               COALESCE(u.username, 'Sistema / Anónimo'),
                               COALESCE(r.name, '—'), a.action, COALESCE(a.summary, '')
                        FROM audit a
                        LEFT JOIN users u ON u.id = a.user_id
                        LEFT JOIN roles r ON r.id = u.role_id
                        WHERE a.entity = 'autenticacion'
                        ORDER BY a.id DESC LIMIT 300''')
            R.update(side_rows=[
                ('Módulo', 'Autenticación y accesos'),
                ('Inicios de sesión', logins_ev),
                ('Alertas / Intentos fallidos', fails_ev),
                ('Seguridad', 'Registra dirección IP de conexión'),
                ('Almacenamiento', 'Histórico permanente en SQLite')
            ])
        elif tab == 'operaciones':
            settable('Historial de operaciones y cambios de datos',
                     ['ID', 'Fecha y hora', 'IP del dispositivo', 'Usuario', 'Rol', 'Acción', 'Módulo', 'Detalle'],
                     '''SELECT a.id, a.created_at, COALESCE(a.ip_address, '127.0.0.1'),
                               COALESCE(u.username, 'Sistema'),
                               COALESCE(r.name, '—'), a.action, a.entity, COALESCE(a.summary, '')
                        FROM audit a
                        LEFT JOIN users u ON u.id = a.user_id
                        LEFT JOIN roles r ON r.id = u.role_id
                        WHERE a.entity NOT IN ('autenticacion', 'usuarios', 'permisos')
                        ORDER BY a.id DESC LIMIT 300''')
            R.update(side_rows=[
                ('Módulo', 'Operaciones y transacciones'),
                ('Registra', 'Socios, unidades, buses, actas, pagos, deudas, multas'),
                ('Trazabilidad', 'Identifica qué usuario realizó cada cambio'),
                ('Detalle', 'Registra importes, nombres y motivos')
            ])
        elif tab == 'seguridad':
            settable('Historial de seguridad y administración',
                     ['ID', 'Fecha y hora', 'IP del dispositivo', 'Usuario', 'Rol', 'Acción', 'Detalle'],
                     '''SELECT a.id, a.created_at, COALESCE(a.ip_address, '127.0.0.1'),
                               COALESCE(u.username, 'Sistema'),
                               COALESCE(r.name, '—'), a.action, COALESCE(a.summary, '')
                        FROM audit a
                        LEFT JOIN users u ON u.id = a.user_id
                        LEFT JOIN roles r ON r.id = u.role_id
                        WHERE a.entity IN ('usuarios', 'permisos') OR a.action LIKE '%clave%' OR a.action LIKE '%rol%' OR a.action LIKE '%permiso%' OR a.action LIKE '%estado%'
                        ORDER BY a.id DESC LIMIT 300''')
            R.update(side_rows=[
                ('Módulo', 'Seguridad y privilegios'),
                ('Registra', 'Cambios de contraseña, roles, permisos y estados'),
                ('Protección', 'Solo accesible para el Administrador'),
                ('Inviolabilidad', 'No modificable por otros usuarios')
            ])
        else:
            settable('Registro general de auditoría',
                     ['ID', 'Fecha y hora', 'IP del dispositivo', 'Usuario', 'Rol', 'Acción', 'Módulo', 'Detalle'],
                     '''SELECT a.id, a.created_at, COALESCE(a.ip_address, '127.0.0.1'),
                               COALESCE(u.username, 'Sistema / Anónimo'),
                               COALESCE(r.name, '—'), a.action, a.entity, COALESCE(a.summary, '')
                        FROM audit a
                        LEFT JOIN users u ON u.id = a.user_id
                        LEFT JOIN roles r ON r.id = u.role_id
                        ORDER BY a.id DESC LIMIT 500''')
            R.update(side_rows=[
                ('Alcance', 'Todo lo que ocurre en el sistema'),
                ('Base de datos', 'Registrado directamente en SQLite'),
                ('Exclusivo', 'Visibilidad exclusiva para Administrador'),
                ('Monitoreo', 'Trazabilidad completa en tiempo real')
            ])
    return R
