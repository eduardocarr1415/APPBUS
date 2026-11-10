"""CSV and PDF reporting with registered transactions and period snapshots."""
from io import BytesIO, StringIO
import csv
from decimal import Decimal
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4

REPORT_TYPES = {
    'general':'Reporte general', 'finanzas':'Reporte financiero',
    'gerencia':'Informe gerencial mensual',
    'deudas':'Reporte de deudas', 'multas':'Reporte de multas',
    'asistencia':'Reporte de asistencia', 'unidades':'Reporte de unidades'
}

def fmt(cents):
    return f'S/ {int(cents or 0)/100:,.2f}'

def build_rows(db, kind, period_id, month=None, fine_cycle_id=None):
    if kind=='gerencia':
        if not month:
            raise ValueError('Seleccione el mes del informe gerencial.')
        income=db.one("SELECT COALESCE(SUM(amount_cents),0) AS total FROM incomes WHERE substr(day,1,7)=?",(month,))['total']
        payments=db.one("SELECT COALESCE(SUM(amount_cents),0) AS total FROM payments WHERE substr(day,1,7)=?",(month,))['total']
        debts=db.one("SELECT COALESCE(SUM(amount_cents),0) AS total FROM debts WHERE substr(issued,1,7)=?",(month,))['total']
        fines=db.one("SELECT COUNT(*) AS count,COALESCE(SUM(amount_cents),0) AS total FROM fines WHERE substr(occurred_at,1,7)=?",(month,))
        meetings=db.one("SELECT COUNT(*) AS count FROM meetings WHERE substr(meeting_date,1,7)=?",(month,))['count']
        attendance=db.one('''SELECT COUNT(*) AS count FROM attendance a JOIN meetings m ON m.id=a.meeting_id
            WHERE substr(m.meeting_date,1,7)=?''',(month,))['count']
        return ['Indicador','Resultado'],[
            ['Ingresos registrados',fmt(income)],
            ['Abonos recibidos',fmt(payments)],
            ['Deudas emitidas',fmt(debts)],
            ['Multas registradas',str(fines['count'])],
            ['Monto de multas registradas',fmt(fines['total'])],
            ['Reuniones realizadas o programadas',str(meetings)],
            ['Registros de asistencia',str(attendance)],
        ]
    if kind == 'finanzas':
        income=db.all('SELECT i.day AS Fecha, i.concept AS Concepto, COALESCE(s.name,\'Compañía\') AS Socio, i.category AS Tipo, i.amount_cents AS Céntimos FROM incomes i LEFT JOIN socios s ON i.socio_id=s.id WHERE i.period_id=? ORDER BY i.day DESC',(period_id,))
        payment=db.all('SELECT p.day AS Fecha, d.concept AS Concepto, s.name AS Socio, \'Pago de deuda\' AS Tipo, p.amount_cents AS Céntimos FROM payments p JOIN debts d ON d.id=p.debt_id JOIN socios s ON s.id=p.socio_id WHERE p.period_id=? ORDER BY p.day DESC',(period_id,))
        return ['Fecha','Concepto','Socio','Tipo','Monto'], [[r['Fecha'],r['Concepto'],r['Socio'],r['Tipo'],fmt(r['Céntimos'])] for r in income+payment]
    if kind=='deudas':
        rows=db.all('SELECT s.name AS Socio,d.concept AS Concepto,d.issued AS Fecha,d.amount_cents AS Total,d.paid_cents AS Abonado FROM debts d JOIN socios s ON s.id=d.socio_id WHERE d.period_id=? ORDER BY d.id DESC',(period_id,))
        return ['Socio','Concepto','Fecha','Total','Abonado','Pendiente'], [[r['Socio'],r['Concepto'],r['Fecha'],fmt(r['Total']),fmt(r['Abonado']),fmt(r['Total']-r['Abonado'])] for r in rows]
    if kind=='multas':
        if fine_cycle_id is not None:
            rows=db.all('SELECT f.occurred_at AS Fecha,s.name AS Socio,f.reason AS Motivo,f.category AS Tipo,f.amount_cents AS Monto,f.status AS Estado FROM fines f JOIN socios s ON s.id=f.socio_id WHERE f.fine_cycle_id=? ORDER BY f.occurred_at DESC,f.id DESC',(fine_cycle_id,))
        else:
            rows=db.all('SELECT f.occurred_at AS Fecha,s.name AS Socio,f.reason AS Motivo,f.category AS Tipo,f.amount_cents AS Monto,f.status AS Estado FROM fines f JOIN socios s ON s.id=f.socio_id WHERE f.period_id=? ORDER BY f.id DESC',(period_id,))
        return ['Fecha','Socio','Motivo','Tipo','Monto','Estado'], [[r['Fecha'],r['Socio'],r['Motivo'],r['Tipo'],fmt(r['Monto']),r['Estado']] for r in rows]
    if kind=='asistencia':
        rows=db.all('SELECT m.meeting_date AS Fecha,m.topic AS Reunión,s.name AS Socio,a.status AS Asistencia FROM attendance a JOIN meetings m ON m.id=a.meeting_id JOIN socios s ON s.id=a.socio_id WHERE m.meeting_date BETWEEN (SELECT starts FROM periods WHERE id=?) AND (SELECT ends FROM periods WHERE id=?) ORDER BY m.meeting_date DESC',(period_id,period_id))
        return ['Fecha','Reunión','Socio','Asistencia'],[[r[x] for x in ('Fecha','Reunión','Socio','Asistencia')] for r in rows]
    if kind=='unidades':
        rows=db.all('SELECT u.code AS Unidad,COALESCE(s.name,\'Sin asignar\') AS Socio,COALESCE(v.plate,\'Sin vehículo\') AS Placa,u.status AS Estado FROM units u LEFT JOIN socios s ON s.id=u.socio_id LEFT JOIN vehicles v ON v.id=u.vehicle_id ORDER BY u.code')
        return ['Unidad','Socio','Placa','Estado'],[[r[x] for x in ('Unidad','Socio','Placa','Estado')] for r in rows]
    # general annual summary
    r=db.one('''SELECT
      (SELECT COALESCE(SUM(amount_cents),0) FROM incomes WHERE period_id=?) AS incomes,
      (SELECT COALESCE(SUM(amount_cents),0) FROM payments WHERE period_id=?) AS payments,
      (SELECT COALESCE(SUM(amount_cents-paid_cents),0) FROM debts WHERE period_id=?) AS pending,
      (SELECT COUNT(*) FROM fines WHERE period_id=?) AS fines,
      (SELECT COUNT(*) FROM meetings WHERE meeting_date BETWEEN (SELECT starts FROM periods WHERE id=?) AND (SELECT ends FROM periods WHERE id=?)) AS meetings,
      (SELECT COUNT(*) FROM socios WHERE active=1) AS socios''',(period_id,period_id,period_id,period_id,period_id,period_id))
    return ['Indicador','Resultado'],[['Ingresos directos',fmt(r['incomes'])],['Pagos de deudas',fmt(r['payments'])],['Total cobrado',fmt(r['incomes']+r['payments'])],['Deuda del periodo pendiente',fmt(r['pending'])],['Multas registradas',str(r['fines'])],['Reuniones',str(r['meetings'])],['Socios activos',str(r['socios'])]]

def as_csv(headers,rows):
    s=StringIO(); w=csv.writer(s); w.writerow(headers)
    for row in rows:
        # Defend spreadsheet viewers against formula injection.
        w.writerow([("'"+str(v) if str(v).startswith(('=','+','-','@')) else v) for v in row])
    return ('\ufeff'+s.getvalue()).encode('utf-8')

def as_pdf(title, period, headers, rows):
    stream=BytesIO()
    doc=SimpleDocTemplate(stream,pagesize=A4, rightMargin=25,leftMargin=25,topMargin=35,bottomMargin=30)
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='BlueTitle',parent=styles['Heading1'],fontSize=16,leading=19,textColor=colors.HexColor('#12366B'),alignment=TA_CENTER,spaceAfter=12))
    styles.add(ParagraphStyle(name='TinyCells',parent=styles['Normal'],fontSize=7,leading=9))
    content=[Paragraph('Compañía de Buses · Sistema de Gestión',styles['BlueTitle']),Paragraph(escape(title),styles['Heading2']),Paragraph(f'Periodo: {escape(period["starts"])} al {escape(period["ends"])}',styles['Normal']),Spacer(1,12)]
    data=[[Paragraph(escape(str(h)),styles['TinyCells']) for h in headers]]
    for row in rows[:1000]:
        data.append([Paragraph(escape(str(v)),styles['TinyCells']) for v in row])
    if len(data)==1: data.append([Paragraph('Sin registros',styles['TinyCells'])]+['']*(len(headers)-1))
    widths=[(A4[0]-50)/max(1,len(headers))]*len(headers)
    t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#E9F1FC')),('GRID',(0,0),(-1,-1),0.2,colors.HexColor('#C9D6E8')),('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#F7F9FD')]),('BOTTOMPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),6)]))
    content.append(t)
    content.append(Spacer(1,12))
    content.append(Paragraph(f'Registros mostrados: {len(rows)}.',styles['Normal']))
    doc.build(content)
    return stream.getvalue()
