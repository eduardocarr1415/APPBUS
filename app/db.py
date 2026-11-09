"""SQLite data model, transactions and parameterized queries."""
import sqlite3
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path

PERMISSIONS = {
    'socios.ver': 'Consultar socios', 'socios.crear': 'Registrar y editar socios',
    'actas.ver': 'Consultar reuniones y actas', 'actas.editar': 'Gestionar reuniones, actas, convocatorias y asistencia',
    'finanzas.ver': 'Consultar economía y deudas', 'finanzas.editar': 'Registrar ingresos, pagos, deudas y marcaciones',
    'multas.ver': 'Consultar multas', 'multas.editar': 'Registrar y actualizar multas',
    'unidades.ver': 'Consultar unidades y vehículos', 'unidades.editar': 'Gestionar unidades y cambios',
    'vigilancia.ver': 'Consultar controles de vigilancia', 'vigilancia.editar': 'Registrar controles de vigilancia',
    'reportes.ver': 'Abrir módulo de reportes',
    'reportes.general': 'Descargar informe general', 'reportes.finanzas': 'Descargar ingresos y pagos',
    'reportes.deudas': 'Descargar deudas', 'reportes.multas': 'Descargar multas',
    'reportes.asistencia': 'Descargar asistencia', 'reportes.unidades': 'Descargar unidades',
    'reportes.vigilancia': 'Descargar vigilancia', 'cierres.ejecutar': 'Cerrar periodos anuales',
    'usuarios.ver': 'Consultar usuarios', 'usuarios.editar': 'Crear y administrar usuarios',
    'roles.editar': 'Administrar roles y permisos', 'auditoria.ver': 'Consultar registro de auditoría',
}
ROLES = {
    'Administrador': list(PERMISSIONS),
    'Secretaría': ['socios.ver','socios.crear','actas.ver','actas.editar','unidades.ver','reportes.ver','reportes.asistencia','reportes.unidades'],
    'Tesorería': ['socios.ver','finanzas.ver','finanzas.editar','multas.ver','unidades.ver','reportes.ver','reportes.finanzas','reportes.deudas','reportes.multas'],
    'Vigilancia': ['socios.ver','multas.ver','multas.editar','unidades.ver','vigilancia.ver','vigilancia.editar','reportes.ver','reportes.multas','reportes.unidades','reportes.vigilancia'],
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
 created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS weekly_marks (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER NOT NULL REFERENCES socios(id),
 week_start TEXT NOT NULL, concept TEXT NOT NULL, amount_cents INTEGER NOT NULL DEFAULT 0 CHECK(amount_cents>=0),
 state TEXT NOT NULL DEFAULT 'Marcado', created_by INTEGER REFERENCES users(id),
 UNIQUE(socio_id,week_start,concept)
);
CREATE TABLE IF NOT EXISTS vigilance (
 id INTEGER PRIMARY KEY, period_id INTEGER NOT NULL REFERENCES periods(id), socio_id INTEGER REFERENCES socios(id),
 unit_id INTEGER REFERENCES units(id), category TEXT NOT NULL, details TEXT NOT NULL, day TEXT NOT NULL,
 created_by INTEGER REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity TEXT NOT NULL, record_id INTEGER, summary TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_incomes_period ON incomes(period_id,day);
CREATE INDEX IF NOT EXISTS idx_payments_period ON payments(period_id,day);
CREATE INDEX IF NOT EXISTS idx_debts_socio ON debts(socio_id);
CREATE INDEX IF NOT EXISTS idx_fines_period ON fines(period_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
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
            for name, ps in ROLES.items():
                existing=con.execute('SELECT id FROM roles WHERE name=?',(name,)).fetchone()
                if existing:
                    continue  # Never re-grant permissions that an administrator previously revoked.
                rid=con.execute('INSERT INTO roles(name) VALUES(?)',(name,)).lastrowid
                for perm in ps:
                    con.execute('INSERT INTO role_permissions(role_id,permission) VALUES(?,?)',(rid,perm))
            self.ensure_period(con, date.today())

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

    def current_period(self):
        with self.connection() as con:
            return self.ensure_period(con,date.today())

    @staticmethod
    def audit(con, uid, action, entity, record_id=None, summary=''):
        con.execute('INSERT INTO audit(user_id,action,entity,record_id,summary) VALUES(?,?,?,?,?)',
                    (uid,action,entity,record_id,summary[:350]))
