# Sistema de Gestión de Compañía de Buses

**Prototipo web funcional en Python + FastAPI + SQLite**, inspirado en los mockups azul y blanco. La interfaz muestra un solo apartado por pestaña para evitar pantallas amontonadas. Los datos de ejemplo son **ficticios**.

## Inicio rápido en Windows

1. Instale **Python 3.11 o posterior** y active la opción *Add Python to PATH*.
2. Extraiga **completamente** el ZIP a una carpeta con permisos de escritura.
3. Haga doble clic en **`INICIAR_WINDOWS.bat`**. En el primer inicio instala las dependencias, crea la base de datos SQLite y configura el acceso administrativo predeterminado (`admin` / `Admin12345678!`), almacenado de forma segura mediante hash criptográfico scrypt (sin credenciales en texto plano en el repositorio).
4. Abra `http://127.0.0.1:8000` e inicie sesión con `admin` y la contraseña `Admin12345678!`. En **Mi perfil** puede cambiarla si lo desea.
5. El iniciador preguntará si desea cargar **datos ficticios de demostración**; responda **S** para ver las tablas y gráficas llenas. También mostrará credenciales temporales aleatorias para Secretaría, Tesorería, Vigilancia y Socio. Guárdelas. No use los datos de prueba como información real.

**Alternativa con terminal** (PowerShell):

```powershell
cd BusGestion_Python_SQLite
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py init
python manage.py demo   # opcional
python run.py
```

Si PowerShell bloquea activar entornos virtuales, puede ejecutar `\.venv\Scripts\python.exe` en lugar de `python` en los cuatro comandos.

## Módulos y pestañas

- **Inicio:** indicadores, deudas por socio, reuniones próximas y actividad.
- **Socios:** registro de socios, asignación de unidades y traspasos de buses con acciones y derechos. El historial conserva cada propietario anterior y nuevo; cada socio puede tener una sola unidad activa.
- **Actas y reuniones:** Actas / Reuniones / Convocatorias / Asistencia; redacción y archivos PDF o imágenes adjuntas. Al marcar una reunión como realizada, la asistencia queda cerrada y el personal autorizado puede generar multas individuales para cada socio ausente, con su deuda asociada y registro de auditoría.
- **Finanzas:** Resumen / Ingresos / Egresos / Deudas / Marcación semanal / Historial. Los egresos registran fecha, categoría, concepto, beneficiario, monto y método de pago. Los abonos a deudas se registran desde Deudas. La marcación aplica un aporte común a todos los socios activos de una fecha; el detalle se abre desde «Ver lista», admite abonos parciales y calcula el pendiente según lo recaudado.
- **Multas:** Multas / Pendientes / Pagadas. Una nueva multa crea una deuda vinculada. Al pagar esa deuda, la multa queda pagada.
- **Unidades y vehículos:** Unidades / Vehículos / Cambios. Se conserva cada reasignación.
- **Vigilancia:** rol de acceso para multas, sin registro digital de las verificaciones diarias de unidades.
- **Cierre anual:** cierre por ciclo de multas con fecha efectiva seleccionable; cada cierre conserva las multas y sus totales.
- **Reportes:** resumen ejecutivo, informes financieros, balance económico mensual de ingresos y egresos, saldo disponible inicial y final calculado con los movimientos registrados, multas por ciclo, asistencia, inventario de unidades e historial de cierres en PDF y CSV. Los controles diarios de unidades no se digitalizan.
- **Usuarios y permisos:** Usuarios / Roles / Permisos / Auditoría.

Los formularios de alta y edición están en pantallas separadas. Los campos se validan en el navegador y nuevamente en el servidor: en socios, nombre, cédula, celular y correo son obligatorios; el nombre solo admite letras y separadores habituales, la cédula solo números hasta 10 dígitos, el celular exactamente 10 y el correo debe tener formato válido. Los errores señalan el campo que debe corregirse. Las demás entradas también tienen límites y validaciones según su tipo. Los cobros originales se guardan como operaciones inmutables: este prototipo no permite editar movimientos históricos para evitar cambios de saldos sin rastro.

## Cuentas y permisos

El administrador crea los usuarios desde la aplicación. **No existe registro público libre**, para evitar que personas no autorizadas se asignen permisos altos.

| Rol | Acceso predeterminado |
| --- | --- |
| Administrador | Todos los módulos, permisos, cierre y administración. |
| Secretaría | Socios, reuniones, actas, convocatorias, asistencia, unidades (lectura), reportes. |
| Tesorería | Finanzas (registro y consulta), socios (lectura), multas/unidades (consulta) y reportes. |
| Vigilancia | Altas y consulta de multas, lectura de socios y unidades, reportes. |
| Socio | Consulta limitada de sus finanzas, multas y unidades, y consulta de actas. Debe vincularse a un socio registrado. |

Los reportes tienen permisos individuales: poder abrir el módulo no concede acceso automático a reportes financieros o datos de asistencia. Solo el administrador gestiona los permisos por rol. El rol Administrador no es editable desde la matriz. Al cambiar un rol o contraseña se invalidan las sesiones anteriores. Se evita desactivar la propia cuenta y quedarse sin administradores activos.

## Seguridad incluida

- Hash de contraseñas **scrypt** con sal única; contraseñas de mínimo 12 caracteres.
- Sesiones **aleatorias almacenadas en SQLite por hash**; cookies HttpOnly, SameSite=Lax, caducidad de 8 horas.
- Protección CSRF en solicitudes POST; bloqueo temporal tras 5 fallos de login por cuenta e IP.
- Comprobación de permisos en el servidor, no solo ocultando botones.
- Consultas SQL parametrizadas, validación de campos e importes en **centavos**, transacciones de pago y auditoría.
- Cabeceras contra marcos y sniffing, CSP que limita scripts externos; contenido de documentos protegido por inicio de sesión.
- Archivos adjuntos limitados a PDF/JPG/PNG y 5 MB, con verificación de la firma del archivo y nombres aleatorios.
- Instalación en `127.0.0.1` de forma predeterminada (no expuesta a internet).

**No debe publicarse tal cual como sistema de producción en Internet.** Antes de usar información real se necesita HTTPS, revisión de seguridad externa, gestión de copias fuera del equipo, pruebas con usuarios, política de privacidad, recuperación de cuentas por canal verificado, límites de almacenamiento, verificación de archivos antivirus y la validación de reglas económicas y legales de la cooperativa. SQLite se recomienda para un despliegue local pequeño; varios usuarios simultáneos podrían requerir PostgreSQL. La recuperación mostrada solo indica contactar al administrador: **no envía correos**.

## Cierre anual del ciclo de multas

El administrador elige la fecha efectiva al realizar cada cierre; no hay una fecha anual fija impuesta. Se cierra únicamente el ciclo de multas acumuladas hasta esa fecha. El ciclo siguiente comienza al día siguiente. El sistema guarda el conteo, monto, pendiente y pagado como resumen del cierre, y conserva todos los registros de multas para consulta y descarga. El cierre no bloquea ni reinicia ingresos, pagos o deudas. No se registran en el sistema las verificaciones diarias de unidades.

## Base de datos, respaldos y rutas

- Base de datos creada automáticamente: `instance/buses.sqlite3`.
- Adjuntos privados: `instance/uploads/`.
- Generar copia consistente de SQLite: `python manage.py backup` (carpeta `copias_seguridad/`). **Haga también copia de `instance/uploads/`**.
- Crear el primer administrador: `python manage.py init`.
- Cargar datos ficticios una sola vez (genera también cuentas y contraseñas aleatorias de prueba): `python manage.py demo`.
- Pruebas (opcional): `python -m pip install -r requirements-dev.txt` y después `python -m pytest -q`.

La app utiliza el puerto 8000; puede cambiarlo con `BUS_PORT`. Para hacer accesible el servicio a otras personas se requiere una implementación de red segura y revisión especializada; **no cambie BUS_HOST a 0.0.0.0 para abrirlo directamente**.

## Limitaciones conocidas del prototipo

Se han implementado los flujos principales de registro, consulta, informes y acceso. Antes del uso real se deben acordar los montos de multas, quién puede aprobar actas, las reglas de cambio de vehículo y qué documentos deben firmarse. La publicación de convocatorias es **interna al sistema** (no envía WhatsApp ni correos). Los reportes CSV se pueden abrir con Excel, aunque no son archivos `.xlsx`. Los datos de demostración no representan valores reales.
