"""Presentation queries for separated, navigable tabs."""
from datetime import date
from .reports import fmt, REPORT_TYPES

NAV = [
 ('dashboard','/','▦','Dashboard',''),
 ('socios','/socios','♙','Socios','socios.ver'),
 ('actas','/actas','▤','Actas y reuniones','actas.ver'),
 ('finanzas','/finanzas','▥','Ingresos económicos','finanzas.ver'),
 ('multas','/multas','⚒','Multas y sanciones','multas.ver'),
 ('unidades','/unidades','▣','Unidades y vehículos','unidades.ver'),
 ('vigilancia','/vigilancia','♢','Vigilancia','vigilancia.ver'),
 ('reportes','/reportes','▥','Reportes','reportes.ver'),
 ('usuarios','/usuarios','♙','Usuarios y permisos','usuarios.ver'),
]
TABS={
 'socios':[('listado','Socios'),('unidades','Unidades asignadas'),('traspasos','Historial de traspasos')],
 'actas':[('actas','Actas'),('reuniones','Reuniones'),('convocatorias','Convocatorias'),('asistencia','Asistencia')],
 'finanzas':[('resumen','Resumen'),('ingresos','Ingresos'),('pagos','Pagos'),('deudas','Deudas'),('marcaciones','Marcación semanal'),('historial','Historial')],
 'multas':[('multas','Multas'),('pendientes','Pendientes'),('pagadas','Pagadas')],
 'unidades':[('unidades','Unidades'),('vehiculos','Vehículos'),('cambios','Cambios de vehículo')],
 'vigilancia':[('controles','Controles'),('sanciones','Sanciones'),('actividad','Actividad')],
 'reportes':[('resumen','Resumen'),('financieros','Financieros'),('multas','Multas'),('asistencia','Asistencia'),('unidades','Unidades'),('cierre','Cierre anual'),('historial','Historial')],
 'usuarios':[('usuarios','Usuarios'),('roles','Roles'),('permisos','Permisos'),('auditoria','Auditoría')],
}
TITLES={'socios':'Socios','actas':'Actas y reuniones','finanzas':'Ingresos económicos','multas':'Multas y sanciones','unidades':'Unidades y vehículos','vigilancia':'Consejo de vigilancia','reportes':'Reportes y cierre anual','usuarios':'Usuarios y permisos'}
SUBTITLES={'socios':'Registro y administración de los socios de la compañía.',
'actas':'Gestión de actas, reuniones, convocatorias y asistencia.',
'finanzas':'Control de ingresos, pagos y deudas de la compañía.',
'multas':'Registro y seguimiento de multas y sanciones.',
'unidades':'Control de vehículos, asignaciones y cambios de unidad.',
'vigilancia':'Seguimiento de controles y actividades de vigilancia.',
'reportes':'Informes administrativos y cierre del 25 de diciembre.',
'usuarios':'Gestión de usuarios, roles, permisos y auditoría.'}

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
            settable('Convocatorias',['ID','Fecha','Reunión','Convocatoria','Publicación'],'''SELECT id,meeting_date,topic,CASE WHEN notice<>'' THEN 'Preparada' ELSE 'Pendiente' END,CASE WHEN notice_sent_at IS NOT NULL THEN 'Publicada' ELSE 'Por publicar' END FROM meetings ORDER BY meeting_date DESC''')
            R.update(new_kind='convocatorias',new_label='Crear convocatoria')
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
        R['cards']=[card('Multas registradas',n,'⚒'),card('Pendientes',pe,'!','orange'),card('Pagadas',db.one("SELECT COUNT(*) n FROM fines f WHERE status='Pagada'"+q,args)['n'],'✓','green')]
        mode='' if tab=='multas' else " AND f.status='Pendiente'" if tab=='pendientes' else " AND f.status='Pagada'"
        settable('Listado de multas',['ID','Fecha','Socio','Motivo','Monto','Estado'],'''SELECT f.id,f.occurred_at,s.name,f.reason,f.amount_cents,f.status FROM fines f JOIN socios s ON s.id=f.socio_id WHERE 1=1'''+q+mode+' ORDER BY f.id DESC LIMIT 150',args,lambda x:[x['id'],x['occurred_at'],x['name'],x['reason'],fmt(x['amount_cents']),x['status']])
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
    elif key=='vigilancia':
        R['cards']=[card('Controles del periodo',db.one('SELECT COUNT(*) n FROM vigilance WHERE period_id=?',(pid,))['n'],'♢'),card('Multas pendientes',db.one("SELECT COUNT(*) n FROM fines WHERE status='Pendiente'")['n'],'⚒')]
        if tab=='sanciones':
            settable('Sanciones de vigilancia',['Fecha','Socio','Motivo','Valor','Estado'],'''SELECT f.occurred_at,s.name,f.reason,f.amount_cents,f.status FROM fines f JOIN socios s ON s.id=f.socio_id WHERE f.period_id=? ORDER BY f.id DESC''',(pid,),lambda x:[x['occurred_at'],x['name'],x['reason'],fmt(x['amount_cents']),x['status']])
            R.update(new_kind='multas',new_label='Registrar multa')
        else:
            settable('Registros de control',['ID','Fecha','Tipo','Socio','Descripción'],'''SELECT v.id,v.day,v.category,COALESCE(s.name,''),v.details FROM vigilance v LEFT JOIN socios s ON s.id=v.socio_id WHERE v.period_id=? ORDER BY v.id DESC''',(pid,))
            R.update(new_kind='vigilancia',new_label='Nuevo control')
    elif key=='reportes':
        R['cards']=[card('Periodo en curso',p['label'],'▦'),card('Fecha de cierre',p['ends'],'▤'),card('Reportes disponibles',len(REPORT_TYPES),'▥')]
        R.update(section='Reportes disponibles',report_types=REPORT_TYPES,periods=db.all('SELECT * FROM periods ORDER BY ends DESC'))
        if tab=='cierre': R.update(section='Cierre anual del 25 de diciembre')
        if tab=='historial':
            settable('Historial de periodos',['Año','Inicio','Fin','Cerrado el'],'''SELECT label,starts,ends,COALESCE(closed_at,'Abierto') FROM periods ORDER BY ends DESC''')
    elif key=='usuarios':
        R['cards']=[card('Usuarios totales',db.one('SELECT COUNT(*) n FROM users')['n'],'♙'),card('Usuarios activos',db.one('SELECT COUNT(*) n FROM users WHERE active=1')['n'],'✓','green'),card('Roles definidos',db.one('SELECT COUNT(*) n FROM roles')['n'],'▧')]
        if tab=='roles':
            settable('Roles existentes',['ID','Rol','Usuarios'],'''SELECT r.id,r.name,COUNT(u.id) FROM roles r LEFT JOIN users u ON u.role_id=r.id GROUP BY r.id ORDER BY r.id''')
        elif tab=='auditoria':
            settable('Auditoría reciente',['Fecha','Usuario','Acción','Entidad','Detalle'],'''SELECT a.created_at,COALESCE(u.username,'Sistema'),a.action,a.entity,COALESCE(a.summary,'') FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100''')
        elif tab=='permisos':
            R.update(section='Permisos por rol',role_rows=db.all('SELECT * FROM roles ORDER BY id'))
        else:
            settable('Usuarios del sistema',['ID','Nombre','Usuario','Rol','Estado'],'''SELECT u.id,u.full_name,u.username,r.name,CASE WHEN u.active=1 THEN 'Activo' ELSE 'Inactivo' END FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id DESC''')
            R.update(new_kind='usuarios',new_label='Nuevo usuario')
    return R
