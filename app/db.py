"""SQLite data model, transactions and parameterized queries."""
import sqlite3
import json
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path
from .security import DEFAULT_ADMIN_PASSWORD_HASH, nowstr

PERMISSIONS = {
    'socios.ver': 'Consultar socios', 'socios.crear': 'Registrar y editar socios',
    'actas.ver': 'Consultar reuniones y actas', 'actas.editar': 'Gestionar reuniones, actas, convocatorias y asistencia',
    'finanzas.ver': 'Consultar ingresos, egresos y deudas', 'finanzas.editar': 'Registrar ingresos, egresos, pagos y deudas',
    'multas.ver': 'Consultar multas', 'multas.editar': 'Registrar y actualizar multas',
    'unidades.ver': 'Consultar unidades y vehículos', 'unidades.editar': 'Gestionar unidades y cambios',
    'reportes.ver': 'Abrir módulo de reportes',
    'reportes.general': 'Descargar informe general', 'reportes.finanzas': 'Descargar informes financieros',
    'reportes.deudas': 'Descargar deudas', 'reportes.multas': 'Descargar multas',
    'reportes.asistencia': 'Descargar asistencia', 'reportes.unidades': 'Descargar unidades',
    'cierres.ejecutar': 'Cerrar el ciclo anual de multas',
    'usuarios.ver': 'Consultar usuarios', 'usuarios.editar': 'Crear y administrar usuarios',
    'roles.editar': 'Administrar roles y permisos', 'auditoria.ver': 'Consultar registro de auditoría',
    'configuracion.ver': 'Configurar y parametrizar página',
    'llegadas.ver': 'Consultar control de llegada de buses',
    'llegadas.editar': 'Registrar llegadas y fotos de buses',
    'llegadas.finalizar': 'Finalizar control diario y generar multas automáticas',
}
ROLES = {
    'Administrador': list(PERMISSIONS),
    'Secretaría': ['socios.ver','socios.crear','actas.ver','actas.editar','unidades.ver','reportes.ver','reportes.asistencia','reportes.unidades','llegadas.ver','llegadas.editar','llegadas.finalizar'],
    'Tesorería': ['socios.ver','finanzas.ver','finanzas.editar','multas.ver','unidades.ver','reportes.ver','reportes.finanzas','reportes.deudas','reportes.multas'],
    'Vigilancia': ['socios.ver','multas.ver','multas.editar','unidades.ver','reportes.ver','reportes.multas','reportes.unidades','llegadas.ver','llegadas.editar','llegadas.finalizar'],
    'Socio': ['actas.ver','finanzas.ver','multas.ver','unidades.ver'],
}
DDL = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS role_permissions (role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, permission TEXT NOT NULL, PRIMARY KEY(role_id,permission));
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, full_name TEXT NOT NULL,
 email TEXT UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role_id INTEGER NOT NULL REFERENCES roles(id),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), socio_id INTEGER REFERENCES socios(id),
 session_version INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts (username TEXT NOT NULL, ip TEXT NOT NULL, tries INTEGER NOT NULL, started_at TEXT NOT NULL, PRIMARY KEY(username,ip));
CREATE TABLE IF NOT EXISTS socios (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, cedula TEXT UNIQUE, phone TEXT, email TEXT,
 joined TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS periods (
 id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE, starts TEXT NOT NULL, ends TEXT NOT NULL,
 closed_at TEXT, closed_by INTEGER REFERENCES users(id), snapshot TEXT, CHECK(starts <= ends)
);
CREATE TABLE IF NOT EXISTS fine_cycles (
 id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE, starts TEXT NOT NULL, ends TEXT,
 closed_at TEXT, closed_by INTEGER REFERENCES users(id), snapshot TEXT,
 source_period_id INTEGER UNIQUE REFERENCES periods(id)
);
CREATE TABLE IF NOT EXISTS vehicles (
 id INTEGER PRIMARY KEY, plate TEXT NOT NULL UNIQUE COLLATE NOCASE, brand TEXT, model TEXT,
 year INTEGER, status TEXT NOT NULL DEFAULT 'Activo', notes TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS units (
 id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE COLLATE NOCASE,
 socio_id INTEGER REFERENCES socios(id), vehicle_id INTEGER REFERENCES vehicles(id),
 status TEXT NOT NULL DEFAULT 'Activa', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS units_single_active_socio_insert
BEFORE INSERT ON units
WHEN NEW.socio_id IS NOT NULL AND NEW.status='Activa'
 AND EXISTS (SELECT 1 FROM units WHERE socio_id=NEW.socio_id AND status='Activa')
BEGIN
 SELECT RAISE(ABORT,'El socio ya tiene una unidad activa.');
END;
CREATE TRIGGER IF NOT EXISTS units_single_active_socio_update
BEFORE UPDATE OF socio_id,status ON units
WHEN NEW.socio_id IS NOT NULL AND NEW.status='Activa'
 AND EXISTS (SELECT 1 FROM units WHERE socio_id=NEW.socio_id AND status='Activa' AND id<>NEW.id)
BEGIN
 SELECT RAISE(ABORT,'El socio ya tiene una unidad activa.');
END;
CREATE TABLE IF NOT EXISTS ownership_transfers (
 id INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL REFERENCES units(id),
 from_socio_id INTEGER NOT NULL REFERENCES socios(id), to_socio_id INTEGER NOT NULL REFERENCES socios(id),
 transferred_at TEXT NOT NULL, includes_shares INTEGER NOT NULL DEFAULT 1 CHECK(includes_shares IN (0,1)),
 includes_rights INTEGER NOT NULL DEFAULT 1 CHECK(includes_rights IN (0,1)),
 document_reference TEXT DEFAULT '', notes TEXT DEFAULT '',
 created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(from_socio_id<>to_socio_id)
);
CREATE TABLE IF NOT EXISTS vehicle_changes (
 id INTEGER PRIMARY KEY, unit_id INTEGER NOT NULL REFERENCES units(id),
 old_vehicle_id INTEGER REFERENCES vehicles(id), new_vehicle_id INTEGER NOT NULL REFERENCES vehicles(id),
 reason TEXT NOT NULL, amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(amount_cents>=0),
 changed_at TEXT NOT NULL, period_id INTEGER NOT NULL REFERENCES periods(id), created_by INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS meetings (
 id INTEGER PRIMARY KEY, type TEXT NOT NULL, topic TEXT NOT NULL, meeting_date TEXT NOT NULL,
 meeting_time TEXT NOT NULL, location TEXT NOT NULL, agenda TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Programada',
 notice TEXT DEFAULT '', notice_sent_at TEXT, minutes TEXT DEFAULT '', minutes_state TEXT NOT NULL DEFAULT 'Borrador',
 created_by INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS attendance (
 meeting_id INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE, socio_id INTEGER NOT NULL REFERENCES socios(id),
 status TEXT NOT NULL CHECK(status IN ('Asistió','Faltó','Justificó')),
 PRIMARY KEY(meeting_id,socio_id)
);
CREATE TABLE IF NOT EXISTS meeting_notifications (
 meeting_id INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE, socio_id INTEGER NOT NULL REFERENCES socios(id),
 notified INTEGER NOT NULL DEFAULT 0 CHECK(notified IN (0,1)), notified_at TEXT,
 PRIMARY KEY(meeting_id,socio_id)
);
CREATE TABLE IF NOT EXISTS docs (id INTEGER PRIMARY KEY, meeting_id INTEGER REFERENCES meetings(id),
 filename TEXT NOT NULL, safe_path TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, uploaded_by INTEGER REFERENCES users(id),
 uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS incomes (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER REFERENCES socios(id),
 concept TEXT NOT NULL, category TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
 method TEXT NOT NULL, day TEXT NOT NULL, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS expenses (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), category TEXT NOT NULL,
 concept TEXT NOT NULL, recipient TEXT NOT NULL DEFAULT '', amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
 method TEXT NOT NULL, day TEXT NOT NULL, created_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS debts (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER NOT NULL REFERENCES socios(id),
 concept TEXT NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>0), paid_cents INTEGER NOT NULL DEFAULT 0,
 issued TEXT NOT NULL, due TEXT, fine_id INTEGER UNIQUE REFERENCES fines(id), created_by INTEGER REFERENCES users(id),
 CHECK(paid_cents>=0 AND paid_cents<=amount_cents)
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), debt_id INTEGER NOT NULL REFERENCES debts(id),
 socio_id INTEGER NOT NULL REFERENCES socios(id), amount_cents INTEGER NOT NULL CHECK(amount_cents>0),
 method TEXT NOT NULL, day TEXT NOT NULL, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS fines (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER NOT NULL REFERENCES socios(id),
 unit_id INTEGER REFERENCES units(id), category TEXT NOT NULL, reason TEXT NOT NULL, occurred_at TEXT NOT NULL,
 amount_cents INTEGER NOT NULL CHECK(amount_cents>0), status TEXT NOT NULL DEFAULT 'Pendiente' CHECK(status IN ('Pendiente','Pagada','Anulada')),
 created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 fine_cycle_id INTEGER REFERENCES fine_cycles(id)
);
CREATE TABLE IF NOT EXISTS meeting_absence_fines (
 meeting_id INTEGER NOT NULL REFERENCES meetings(id), socio_id INTEGER NOT NULL REFERENCES socios(id),
 fine_id INTEGER NOT NULL UNIQUE REFERENCES fines(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(meeting_id,socio_id)
);
CREATE TABLE IF NOT EXISTS weekly_marks (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER NOT NULL REFERENCES socios(id),
 week_start TEXT NOT NULL, concept TEXT NOT NULL, amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(amount_cents>=0),
 paid_cents INTEGER NOT NULL DEFAULT 0 CHECK(paid_cents>=0 AND paid_cents<=amount_cents),
 state TEXT NOT NULL DEFAULT 'Pendiente' CHECK(state IN ('Pendiente','Pagado')),
 paid_at TEXT, payment_method TEXT, income_id INTEGER UNIQUE REFERENCES incomes(id),
 created_by INTEGER REFERENCES users(id),
 UNIQUE(socio_id,week_start,concept)
);
CREATE TABLE IF NOT EXISTS vigilance (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER REFERENCES socios(id),
 unit_id INTEGER REFERENCES units(id), category TEXT NOT NULL, details TEXT NOT NULL, day TEXT NOT NULL,
 created_by INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity TEXT NOT NULL, record_id INTEGER, summary TEXT, ip_address TEXT DEFAULT '127.0.0.1',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS system_settings (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bus_arrival_days (
 id INTEGER PRIMARY KEY,
 day TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'Abierto' CHECK(status IN ('Abierto', 'Finalizado')),
 interval_minutes INTEGER NOT NULL DEFAULT 10 CHECK(interval_minutes > 0),
 start_time TEXT NOT NULL DEFAULT '08:00',
 end_time TEXT NOT NULL DEFAULT '19:00',
 control_point TEXT NOT NULL DEFAULT 'Punto 1 - Esquina Principal',
 fine_amount_cents INTEGER NOT NULL DEFAULT 500 CHECK(fine_amount_cents >= 0),
 closed_at TEXT,
 closed_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS bus_arrival_slots (
 id INTEGER PRIMARY KEY,
 day_id INTEGER NOT NULL REFERENCES bus_arrival_days(id) ON DELETE CASCADE,
 day TEXT NOT NULL,
 scheduled_time TEXT NOT NULL,
 unit_id INTEGER REFERENCES units(id),
 socio_id INTEGER REFERENCES socios(id),
 photo_path TEXT,
 photo_filename TEXT,
 registered_at TEXT,
 registered_by INTEGER REFERENCES users(id),
 status TEXT NOT NULL DEFAULT 'Pendiente' CHECK(status IN ('Pendiente', 'Registrado', 'Expirado', 'Multado')),
 fine_id INTEGER UNIQUE REFERENCES fines(id),
 notes TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(day, scheduled_time)
);
CREATE INDEX IF NOT EXISTS idx_incomes_period ON incomes(period_id,day);
CREATE INDEX IF NOT EXISTS idx_expenses_period ON expenses(period_id,day);
CREATE INDEX IF NOT EXISTS idx_payments_period ON payments(period_id,day);
CREATE INDEX IF NOT EXISTS idx_debts_socio ON debts(socio_id);
CREATE INDEX IF NOT EXISTS idx_fines_period ON fines(period_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
CREATE INDEX IF NOT EXISTS idx_bus_arrival_slots_day ON bus_arrival_slots(day, scheduled_time);
"""

class Database:
    def __init__(self, path):
        self.path = str(Path(path).resolve())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self):
        con = sqlite3.connect(self.path, timeout=15)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('PRAGMA busy_timeout=15000')
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def all(self, sql, params=()):
        with self.connection() as con:
            return [dict(row) for row in con.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        with self.connection() as con:
            row = con.execute(sql, params).fetchone()
            return dict(row) if row else None

    def init(self):
        with self.connection() as con:
            con.executescript(DDL)
            con.execute('PRAGMA journal_mode=WAL')
            cols = [c[1] for c in con.execute('PRAGMA table_info(audit)').fetchall()]
            if 'ip_address' not in cols:
                con.execute("ALTER TABLE audit ADD COLUMN ip_address TEXT DEFAULT '127.0.0.1'")
            for name, ps in ROLES.items():
                existing=con.execute('SELECT id FROM roles WHERE name=?',(name,)).fetchone()
                if existing:
                    continue  # Never re-grant permissions that an administrator previously revoked.
                rid=con.execute('INSERT INTO roles(name) VALUES(?)',(name,)).lastrowid
                for perm in ps:
                    con.execute('INSERT INTO role_permissions(role_id,permission) VALUES(?,?)',(rid,perm))
            admin_row = con.execute("SELECT id FROM roles WHERE name='Administrador'").fetchone()
            if admin_row:
                con.execute("INSERT OR IGNORE INTO role_permissions(role_id, permission) VALUES(?, 'configuracion.ver')", (admin_row['id'],))
                for p in ['llegadas.ver', 'llegadas.editar', 'llegadas.finalizar']:
                    con.execute("INSERT OR IGNORE INTO role_permissions(role_id, permission) VALUES(?, ?)", (admin_row['id'], p))
            sec_row = con.execute("SELECT id FROM roles WHERE name='Secretaría'").fetchone()
            if sec_row:
                for p in ['llegadas.ver', 'llegadas.editar', 'llegadas.finalizar']:
                    con.execute("INSERT OR IGNORE INTO role_permissions(role_id, permission) VALUES(?, ?)", (sec_row['id'], p))
            vig_row = con.execute("SELECT id FROM roles WHERE name='Vigilancia'").fetchone()
            if vig_row:
                for p in ['llegadas.ver', 'llegadas.editar', 'llegadas.finalizar']:
                    con.execute("INSERT OR IGNORE INTO role_permissions(role_id, permission) VALUES(?, ?)", (vig_row['id'], p))
            self.ensure_period(con, date.today())
            self.migrate_fine_cycles(con)
            self.migrate_weekly_marks(con)
            con.execute("DELETE FROM role_permissions WHERE permission IN ('vigilancia.ver','vigilancia.editar','reportes.vigilancia')")
            self.ensure_fine_cycle(con,date.today())
            self.purge_expired(con, nowstr())

    def ensure_default_admin(self, force_reset=False):
        """Create the 'admin' account if missing.

        Only when force_reset=True (CLI `manage.py reset-admin`) is an existing admin's
        password restored to the default hash; otherwise a password changed by the
        administrator survives restarts."""
        with self.connection() as con:
            admin_role = con.execute("SELECT id FROM roles WHERE name='Administrador'").fetchone()
            if not admin_role:
                return
            role_id = admin_role['id']
            admin_user = con.execute("SELECT id, password_hash FROM users WHERE username='admin'").fetchone()
            if not admin_user:
                con.execute(
                    "INSERT INTO users(username, full_name, email, password_hash, role_id, active) VALUES(?,?,?,?,?,1)",
                    ('admin', 'Administrador principal', None, DEFAULT_ADMIN_PASSWORD_HASH, role_id)
                )
                Database.audit(con, None, 'Inicializar', 'sistema', None, 'Administrador predeterminado configurado.')
            elif force_reset:
                con.execute(
                    "UPDATE users SET password_hash=?, active=1, role_id=?, session_version=session_version+1 WHERE username='admin'",
                    (DEFAULT_ADMIN_PASSWORD_HASH, role_id)
                )
                con.execute("DELETE FROM sessions WHERE user_id=?", (admin_user['id'],))
                Database.audit(con, None, 'Restablecer clave', 'usuarios', admin_user['id'],
                               "Contraseña de 'admin' restablecida desde la consola (manage.py reset-admin).")

    @staticmethod
    def purge_expired(con, now_iso):
        """Remove expired sessions so anonymous visits do not grow the table indefinitely."""
        con.execute('DELETE FROM sessions WHERE expires_at<=?', (now_iso,))

    @staticmethod
    def migrate_fine_cycles(con):
        columns={row['name'] for row in con.execute('PRAGMA table_info(fines)').fetchall()}
        if 'fine_cycle_id' not in columns:
            con.execute('ALTER TABLE fines ADD COLUMN fine_cycle_id INTEGER REFERENCES fine_cycles(id)')
        con.execute('CREATE INDEX IF NOT EXISTS idx_fines_cycle ON fines(fine_cycle_id,occurred_at)')
        periods=con.execute('SELECT * FROM periods ORDER BY starts,id').fetchall()
        for period in periods:
            cycle=con.execute('SELECT id FROM fine_cycles WHERE source_period_id=?',(period['id'],)).fetchone()
            if cycle:
                cycle_id=cycle['id']
            else:
                totals=con.execute('''SELECT COUNT(*) AS count,COALESCE(SUM(amount_cents),0) AS total,
                    COALESCE(SUM(CASE WHEN status='Pendiente' THEN amount_cents ELSE 0 END),0) AS pending
                    FROM fines WHERE period_id=?''',(period['id'],)).fetchone()
                snapshot=json.dumps(dict(totals),ensure_ascii=False)
                end=period['ends'] if period['closed_at'] else None
                cycle_id=con.execute('''INSERT INTO fine_cycles
                    (label,starts,ends,closed_at,closed_by,snapshot,source_period_id)
                    VALUES(?,?,?,?,?,?,?)''',
                    (period['label'],period['starts'],end,period['closed_at'],
                     period['closed_by'],snapshot,period['id'])).lastrowid
            con.execute('UPDATE fines SET fine_cycle_id=? WHERE period_id=? AND fine_cycle_id IS NULL',
                        (cycle_id,period['id']))

    @staticmethod
    def migrate_weekly_marks(con):
        columns={row['name'] for row in con.execute('PRAGMA table_info(weekly_marks)').fetchall()}
        if 'paid_at' not in columns:
            con.execute('ALTER TABLE weekly_marks ADD COLUMN paid_at TEXT')
        if 'payment_method' not in columns:
            con.execute('ALTER TABLE weekly_marks ADD COLUMN payment_method TEXT')
        if 'income_id' not in columns:
            con.execute('ALTER TABLE weekly_marks ADD COLUMN income_id INTEGER REFERENCES incomes(id)')
        if 'paid_cents' not in columns:
            con.execute('ALTER TABLE weekly_marks ADD COLUMN paid_cents INTEGER NOT NULL DEFAULT 0 CHECK(paid_cents>=0)')
        con.execute("UPDATE weekly_marks SET paid_cents=amount_cents WHERE state='Pagado' AND paid_cents=0")
        con.execute("UPDATE weekly_marks SET state='Pendiente' WHERE state NOT IN ('Pagado','Pendiente')")
        con.execute('CREATE INDEX IF NOT EXISTS idx_weekly_marks_date ON weekly_marks(week_start,socio_id)')

    @staticmethod
    def ensure_period(con, today):
        ending = today.year if today <= date(today.year,12,25) else today.year+1
        label=str(ending)
        row=con.execute('SELECT * FROM periods WHERE label=?',(label,)).fetchone()
        if row:
            return dict(row)
        start=f'{ending-1}-12-26'; end=f'{ending}-12-25'
        con.execute('INSERT INTO periods(label,starts,ends) VALUES(?,?,?)',(label,start,end))
        return dict(con.execute('SELECT * FROM periods WHERE label=?',(label,)).fetchone())

    @staticmethod
    def ensure_fine_cycle(con,today):
        row=con.execute('SELECT * FROM fine_cycles WHERE closed_at IS NULL ORDER BY id DESC LIMIT 1').fetchone()
        if row:
            return dict(row)
        previous=con.execute('SELECT ends FROM fine_cycles WHERE ends IS NOT NULL ORDER BY ends DESC,id DESC LIMIT 1').fetchone()
        start=(date.fromisoformat(previous['ends'])+timedelta(days=1)).isoformat() if previous else Database.ensure_period(con,today)['starts']
        year=start[:4]
        count=con.execute('SELECT COUNT(*) AS n FROM fine_cycles WHERE label LIKE ?',(year+'%',)).fetchone()['n']
        label=year if count==0 else f'{year}-{count+1}'
        cycle_id=con.execute('INSERT INTO fine_cycles(label,starts) VALUES(?,?)',(label,start)).lastrowid
        return dict(con.execute('SELECT * FROM fine_cycles WHERE id=?',(cycle_id,)).fetchone())

    @staticmethod
    def ensure_arrival_day(con, day_str, interval_minutes=10, start_time='08:00', end_time='19:00', control_point='Punto 1 - Esquina Principal', fine_amount_cents=500):
        day_row = con.execute("SELECT * FROM bus_arrival_days WHERE day=?", (day_str,)).fetchone()
        if not day_row:
            con.execute("""INSERT INTO bus_arrival_days (day, status, interval_minutes, start_time, end_time, control_point, fine_amount_cents)
                           VALUES (?, 'Abierto', ?, ?, ?, ?, ?)""",
                        (day_str, interval_minutes, start_time, end_time, control_point, fine_amount_cents))
            day_id = con.execute("SELECT id FROM bus_arrival_days WHERE day=?", (day_str,)).fetchone()['id']
            try:
                start_h, start_m = map(int, start_time.split(':'))
                end_h, end_m = map(int, end_time.split(':'))
            except Exception:
                start_h, start_m = 8, 0
                end_h, end_m = 19, 0
            cur_min = start_h * 60 + start_m
            end_min = end_h * 60 + end_m
            if interval_minutes <= 0:
                interval_minutes = 10
            while cur_min <= end_min:
                hh = cur_min // 60
                mm = cur_min % 60
                time_str = f"{hh:02d}:{mm:02d}"
                con.execute("""INSERT OR IGNORE INTO bus_arrival_slots (day_id, day, scheduled_time, unit_id, socio_id, status)
                               VALUES (?, ?, ?, NULL, NULL, 'Pendiente')""",
                            (day_id, day_str, time_str))
                cur_min += interval_minutes
            day_row = con.execute("SELECT * FROM bus_arrival_days WHERE id=?", (day_id,)).fetchone()
        return dict(day_row)

    def current_period(self):
        with self.connection() as con:
            return self.ensure_period(con,date.today())

    def current_fine_cycle(self):
        with self.connection() as con:
            return self.ensure_fine_cycle(con,date.today())

    @staticmethod
    def audit(con, uid, action, entity, record_id=None, summary='', ip=None):
        con.execute('INSERT INTO audit(user_id,action,entity,record_id,summary,ip_address) VALUES(?,?,?,?,?,?)',
                    (uid,action,entity,record_id,summary[:350],ip or '127.0.0.1'))

    DEFAULT_SETTINGS = {
        # Identidad y textos
        'company_name': 'Compañía de Transportes Guaytacama',
        'company_slogan': 'Buses Guaytacama · Servicio Interparroquial e Interprovincial',
        'footer_text': 'Transportes Guaytacama · Sistema de Control Operativo y Flota',
        'login_title': 'Sistema de Gestión de Compañía de Buses',
        'login_subtitle': 'Accede a la plataforma de gestión de la compañía.',

        # Logos e imágenes
        'header_logo_url': '/static/bus-icon.svg',
        'sidebar_banner_url': '/static/bus-guaytacama.svg',
        'login_banner_url': '/static/bus-landscape.svg',
        'favicon_url': '/static/favicon.svg',

        # Colores y estilo
        'primary_color': '#1d4ed8',
        'sidebar_color': '#0f172a',
        'accent_color': '#f59e0b',
        'page_bg_color': '#f8fafc',
        'card_bg_color': '#ffffff',
        'sidebar_text_color': '#e2e8f0',
        'border_radius': '14px',

        # Tipografía
        'font_family': "Inter, system-ui, -apple-system, sans-serif",
        'font_size': '14px',

        # Pestañas (Tabs)
        'tabs_style': 'capsule',  # capsule, underline, pills, segmented

        # Iconos de módulos
        'icon_dashboard': '▦',
        'icon_socios': '♙',
        'icon_actas': '▤',
        'icon_finanzas': '▥',
        'icon_multas': '⚒',
        'icon_unidades': '▣',
        'icon_reportes': '▥',
        'icon_usuarios': '♙',
        'icon_auditoria': '⏱',
        'icon_configuracion': '⚙',

        # Títulos de módulos
        'title_dashboard': 'Dashboard',
        'title_socios': 'Socios',
        'title_actas': 'Actas y reuniones',
        'title_finanzas': 'Finanzas',
        'title_multas': 'Multas',
        'title_unidades': 'Unidades y vehículos',
        'title_reportes': 'Reportes',
        'title_usuarios': 'Usuarios y permisos',
        'title_auditoria': 'Historial del sistema',
        'title_configuracion': 'Configurar página',

        # Animación del bus (Desactivada por defecto para navegación inmediata sin esperas)
        'bus_animation': '0',
        'animation_duration': '1.8',
        'bus_led_text': 'GUAYTACAMA',
        'bus_badge_tag': 'RUTA GUAYTACAMA',
        'bus_badge_sub': 'Buses Guaytacama · Puntualidad, Confort y Seguridad'
    }

    def get_settings(self):
        settings = dict(self.DEFAULT_SETTINGS)
        try:
            with self.connection() as con:
                con.execute('CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
                rows = con.execute('SELECT key, value FROM system_settings').fetchall()
                for r in rows:
                    settings[r['key']] = r['value']
        except Exception:
            pass
        return settings

    def update_settings(self, new_settings):
        with self.connection() as con:
            con.execute('CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            for k, v in new_settings.items():
                if k in self.DEFAULT_SETTINGS:
                    con.execute('INSERT INTO system_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, str(v)))

    def reset_settings(self):
        with self.connection() as con:
            con.execute('DELETE FROM system_settings')
