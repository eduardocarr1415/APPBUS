"""Authentication and input validation; dependencies are stdlib-only."""
import base64
import hashlib
import hmac
import re
import secrets
import unicodedata
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal, InvalidOperation
from html import escape

LOGIN_WINDOW = 15
MAX_ATTEMPTS = 5
SESSION_HOURS = 8

def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return f'scrypt:16384:8:1${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}'

def password_ok(password, stored):
    try:
        scheme, salt_enc, hash_enc = stored.split('$')
        if scheme != 'scrypt:16384:8:1': return False
        derived=hashlib.scrypt(password.encode('utf-8'), salt=base64.b64decode(salt_enc), n=2**14,r=8,p=1,dklen=64)
        return hmac.compare_digest(derived, base64.b64decode(hash_enc))
    except (ValueError, TypeError):
        return False

def password_valid(pwd):
    return 12 <= len(pwd) <= 128 and not pwd.isspace()

def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)

def nowstr():
    return utcnow().isoformat()

def expires(hours=SESSION_HOURS):
    return (utcnow()+timedelta(hours=hours)).isoformat()

def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def make_session(con, user_id=None, version=0):
    token=secrets.token_urlsafe(48)
    csrf=secrets.token_urlsafe(32)
    con.execute('INSERT INTO sessions(token_hash,user_id,csrf,version,expires_at) VALUES(?,?,?,?,?)',
                (token_hash(token),user_id,csrf,version,expires()))
    return token,csrf

def money(text):
    s=str(text or '').strip().replace(',','.')
    if not re.fullmatch(r'\d{1,10}(?:\.\d{1,2})?', s):
        raise ValueError('Ingrese un monto válido con hasta dos decimales.')
    try:
        cents=int((Decimal(s)*100).to_integral_exact())
    except InvalidOperation:
        raise ValueError('Monto inválido.')
    if cents>999999999999: raise ValueError('Monto demasiado grande.')
    return cents

def valid_date(value):
    try: return date.fromisoformat(str(value))
    except ValueError: raise ValueError('La fecha no es válida.')

def safe_text(value, label='Campo', maxlen=250, required=True):
    s=str(value or '').strip()
    if required and not s: raise ValueError(f'{label}: este campo es obligatorio.')
    if len(s)>maxlen: raise ValueError(f'{label}: máximo {maxlen} caracteres.')
    if any(ord(ch)<32 and ch not in '\n\t' for ch in s): raise ValueError(f'{label}: contiene caracteres no válidos.')
    return s

def valid_person_name(value, label='Nombre', maxlen=120, required=True):
    s=safe_text(value,label,maxlen,required)
    if not s: return s
    separators={" ", "'", "’", "-"}
    for index,char in enumerate(s):
        category=unicodedata.category(char)
        if category.startswith('L'):
            continue
        if category.startswith('M'):
            if index and unicodedata.category(s[index-1]).startswith(('L','M')):
                continue
        if char in separators:
            if (not index or index==len(s)-1 or s[index-1] in separators
                    or s[index+1] in separators):
                raise ValueError(f'{label}: use solo letras, espacios, apóstrofes o guiones.')
            continue
        raise ValueError(f'{label}: use solo letras, espacios, apóstrofes o guiones.')
    if (unicodedata.category(s[0]).startswith('L')
            and unicodedata.category(s[-1]).startswith(('L','M'))):
        return s
    raise ValueError(f'{label}: use solo letras, espacios, apóstrofes o guiones.')

def valid_cedula(value):
    s=str(value or '').strip()
    if s and not re.fullmatch(r'[0-9]{1,10}',s):
        raise ValueError('Cédula: ingrese solo números, hasta 10 dígitos.')
    return s

def valid_phone(value):
    s=str(value or '').strip()
    if s and not re.fullmatch(r'[0-9]{10}',s):
        raise ValueError('Celular: ingrese exactamente 10 números.')
    return s

def valid_username(s):
    s=(s or '').strip()
    if not re.fullmatch(r'[\w.\-]{3,32}',s,re.UNICODE): raise ValueError('El usuario debe tener 3 a 32 letras, números, guiones o puntos.')
    return s

def valid_email(s):
    s=(s or '').strip().lower()
    if s:
        if len(s)>254 or s.count('@')!=1:
            raise ValueError('El correo no tiene un formato válido.')
        local,domain=s.rsplit('@',1)
        labels=domain.split('.')
        if (len(local)>64 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+",local)
                or local.startswith('.') or local.endswith('.') or '..' in local
                or len(labels)<2 or any(
                    not label or len(label)>63 or label.startswith('-') or label.endswith('-')
                    or not re.fullmatch(r'[A-Za-z0-9-]+',label) for label in labels
                )
                or not re.fullmatch(r'[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59}',labels[-1])):
            raise ValueError('El correo no tiene un formato válido.')
    return s

def locked(con, username, ip):
    row=con.execute('SELECT * FROM login_attempts WHERE username=? AND ip=?',(username.lower(),ip)).fetchone()
    if not row: return False
    when=datetime.fromisoformat(row['started_at'])
    if utcnow()-when>timedelta(minutes=LOGIN_WINDOW):
        con.execute('DELETE FROM login_attempts WHERE username=? AND ip=?',(username.lower(),ip))
        return False
    return row['tries']>=MAX_ATTEMPTS

def register_failure(con, username, ip):
    username=username.lower()
    con.execute('INSERT INTO login_attempts(username,ip,tries,started_at) VALUES(?,?,1,?) '
                'ON CONFLICT(username,ip) DO UPDATE SET tries=tries+1', (username,ip,nowstr()))

def reset_failures(con, username, ip):
    con.execute('DELETE FROM login_attempts WHERE username=? AND ip=?',(username.lower(),ip))
