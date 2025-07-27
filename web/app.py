from flask import Flask, render_template, request, redirect, session, jsonify, Response, send_from_directory, flash
import bcrypt
import csv
from datetime import datetime, date, timedelta, time # Importar 'time' para isinstance
from utils.db import get_connection
from flask_cors import CORS
import paho.mqtt.publish as publish
import json
import io
import os # Importar os para manejo de rutas de archivos
from mysql.connector import Error as MySQLC_Error
import re # Para validación de UUID con regex
import time as time_module # Usar alias para evitar conflicto con datetime.time

# Importar Flask-CSRFProtect
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Importar elementos de ReportLab para generación de PDF
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib import colors # Importar colors para otros usos si fuera necesario
from reportlab.lib.units import inch

app = Flask(__name__)
# ¡IMPORTANTE! Esta clave debe ser larga, aleatoria y SECRETA en producción.
# Se usa para firmar cookies de sesión y tokens CSRF.
app.secret_key = 'H*48Vz#+6@qbgXfBU!HmZk-4uwKwQCxC*rdzK7DSxw34-bV#fcZhd8suVSmP3+XA'
CORS(app)

# Inicializar CSRFProtect
csrf = CSRFProtect(app)

MQTT_BROKER_HOST = 'localhost'
MQTT_BROKER_PORT = 1883
MQTT_TOPIC_UNLOCK = 'etec/cerraduras/{}/unlock'

# Define the assets folder for static files like images
# Ensure 'assets' folder is at the same level as app.py
ASSETS_FOLDER = os.path.join(app.root_path, 'assets')

# --- Variables para Protección contra Fuerza Bruta (en memoria, para demo) ---
# En producción, esto debería ser persistente (ej. Redis, base de datos)
LOGIN_ATTEMPTS = {} # {username: count}
LAST_ATTEMPT_TIME = {} # {username: timestamp}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300 # 5 minutos en segundos

### Funciones Auxiliares ###

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_user' not in session:
            # Redirigir a login si no está autenticado
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def normalize_hora(hora_str):
    """Convierte 'H:MM' o 'HH:MM' en 'HH:MM' con ceros a la izquierda."""
    h, m = hora_str.split(':')
    return f"{int(h):02d}:{int(m):02d}"

def publish_mqtt_command(topic, message):
    """
    Publica un comando MQTT.
    En producción, considera usar TLS para la conexión MQTT.
    Ejemplo:
    import ssl
    context = ssl.create_default_context()
    context.load_verify_locations('path/to/ca.crt') # Certificado de la CA del broker
    # context.load_cert_chain('path/to/client.crt', 'path/to/client.key') # Si el cliente necesita autenticación
    publish.single(topic, payload=message, hostname=MQTT_BROKER_HOST, port=MQTT_BROKER_PORT,
                   tls=context, protocol=paho.mqtt.client.MQTTv311)
    """
    try:
        publish.single(topic, payload=message, hostname=MQTT_BROKER_HOST, port=MQTT_BROKER_PORT)
        print(f"Comando MQTT publicado: Topic='{topic}', Message='{message}'")
    except Exception as e:
        print(f"Error al publicar comando MQTT: {e}")

# --- Funciones de Validación ---
def is_valid_uuid(uuid_str):
    """Valida un UUID RFID en formato XX-XX-XX-XX (4 bytes, 8 hex) o XX-XX-XX-XX-XX-XX (6 bytes, 12 hex)."""
    return re.fullmatch(r'^([0-9a-fA-F]{2}-){3}[0-9a-fA-F]{2}$', uuid_str) is not None or \
           re.fullmatch(r'^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$', uuid_str) is not None


### Rutas de Autenticación ###

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # --- Protección contra Fuerza Bruta ---
        current_time = time_module.time() # Usar time_module.time()
        if username in LAST_ATTEMPT_TIME and (current_time - LAST_ATTEMPT_TIME[username] < LOCKOUT_TIME):
            if LOGIN_ATTEMPTS.get(username, 0) >= MAX_LOGIN_ATTEMPTS:
                flash(f'Demasiados intentos de inicio de sesión fallidos para {username}. Intenta de nuevo en {LOCKOUT_TIME} segundos.', 'error')
                return render_template('login.html', csrf_token=generate_csrf()) # Eliminado error=True
        
        conn = get_connection()
        if conn is None:
            flash("Error de conexión a la base de datos.", 'error')
            return render_template('login.html', csrf_token=generate_csrf()) # Eliminado error=True

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admins WHERE username = %s", (username,))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['hashed_password'].encode('utf-8')):
            session['admin_user'] = username
            # Restablecer intentos de login al éxito
            LOGIN_ATTEMPTS.pop(username, None)
            LAST_ATTEMPT_TIME.pop(username, None)
            print(f"AUDITORIA: Inicio de sesión exitoso para el usuario: {username}")
            return redirect('/dashboard')
        else:
            # Incrementar intentos de login fallidos
            LOGIN_ATTEMPTS[username] = LOGIN_ATTEMPTS.get(username, 0) + 1
            LAST_ATTEMPT_TIME[username] = current_time
            print(f"AUDITORIA: Intento de inicio de sesión fallido para el usuario: {username}")
            flash('Usuario o contraseña incorrectos.', 'error')
            return render_template('login.html', csrf_token=generate_csrf()) # Eliminado error=True
    
    # Añadir el token CSRF para el formulario de login (GET request)
    return render_template('login.html', csrf_token=generate_csrf())

@app.route('/logout')
@login_required
def logout():
    username = session.get('admin_user', 'Desconocido')
    session.pop('admin_user', None)
    print(f"AUDITORIA: Cierre de sesión para el usuario: {username}")
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect('/')

### Rutas del Dashboard ###

@app.route('/dashboard')
@login_required
def dashboard():
    # Pasar el token CSRF a la plantilla para todos los formularios
    return render_template('dashboard.html', csrf_token=generate_csrf())

### APIs para Laboratorios (Cerraduras) ###

@app.route('/api/laboratorios', methods=['GET'])
@login_required
def get_laboratorios():
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM laboratorios")
        laboratorios = cursor.fetchall()
        return jsonify(laboratorios)
    except Exception as e:
        print(f"Error al obtener laboratorios: {e}")
        return jsonify({"error": "Error interno del servidor al obtener laboratorios"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/laboratorios', methods=['POST'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def create_laboratorio():
    data = request.json
    nombre = data.get('nombre')
    topic_mqtt = data.get('topic_mqtt')

    # --- Validación de Entradas ---
    if not nombre or not topic_mqtt:
        return jsonify({"error": "Nombre y Topic MQTT son obligatorios"}), 400
    if len(nombre) > 100:
        return jsonify({"error": "El nombre del laboratorio es demasiado largo."}), 400
    if not re.match(r'^[a-zA-Z0-9_-]+$', topic_mqtt): # Ejemplo: solo letras, números, guiones y guiones bajos
        return jsonify({"error": "El Topic MQTT contiene caracteres no permitidos."}), 400
    if len(topic_mqtt) > 50:
        return jsonify({"error": "El Topic MQTT es demasiado largo."}), 400

    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO laboratorios (nombre, topic_mqtt, creado_en) VALUES (%s, %s, NOW())",
                       (nombre, topic_mqtt))
        conn.commit()
        print(f"AUDITORIA: Laboratorio '{nombre}' creado por {session['admin_user']}")
        return jsonify({"message": "Laboratorio creado exitosamente"}), 201
    except Exception as e:
        conn.rollback()
        print(f"Error al crear laboratorio: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/laboratorios/<int:id>', methods=['PUT'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def update_laboratorio(id):
    data = request.json
    nombre = data.get('nombre')
    topic_mqtt = data.get('topic_mqtt')

    # --- Validación de Entradas ---
    if not nombre or not topic_mqtt:
        return jsonify({"error": "Nombre y Topic MQTT son obligatorios"}), 400
    if len(nombre) > 100:
        return jsonify({"error": "El nombre del laboratorio es demasiado largo."}), 400
    if not re.match(r'^[a-zA-Z0-9_-]+$', topic_mqtt):
        return jsonify({"error": "El Topic MQTT contiene caracteres no permitidos."}), 400
    if len(topic_mqtt) > 50:
        return jsonify({"error": "El Topic MQTT es demasiado largo."}), 400

    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE laboratorios SET nombre=%s, topic_mqtt=%s WHERE id=%s",
                       (nombre, topic_mqtt, id))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Laboratorio no encontrado"}), 404
        print(f"AUDITORIA: Laboratorio ID {id} actualizado por {session['admin_user']}")
        return jsonify({"message": "Laboratorio actualizado exitosamente"}), 200
    except Exception as e:
        conn.rollback()
        print(f"Error al actualizar laboratorio: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/laboratorios/<int:id>', methods=['DELETE'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def delete_laboratorio(id):
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM laboratorios WHERE id=%s", (id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Laboratorio no encontrado"}), 404
        print(f"AUDITORIA: Laboratorio ID {id} eliminado por {session['admin_user']}")
        return jsonify({"message": "Laboratorio eliminado exitosamente"}), 200
    except Exception as e:
        conn.rollback()
        print(f"Error al eliminar laboratorio: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

### APIs para Control de Cerraduras ###

@app.route('/api/cerraduras/<int:laboratorio_id>/unlock', methods=['POST'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def unlock_cerradura(laboratorio_id):
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT topic_mqtt, nombre FROM laboratorios WHERE id = %s", (laboratorio_id,))
    laboratorio = cursor.fetchone()
    cursor.close()
    conn.close()

    if not laboratorio:
        return jsonify({"error": "Laboratorio no encontrado"}), 404

    topic = MQTT_TOPIC_UNLOCK.format(laboratorio['topic_mqtt'])
    message = json.dumps({"command": "unlock", "source": "admin_app", "user": session['admin_user']})

    publish_mqtt_command(topic, message)

    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO registros_acceso (laboratorio_id, tipo_acceso, usuario_admin, resultado, creado_en) VALUES (%s, %s, %s, %s, NOW())",
            (laboratorio_id, 'apertura_manual_admin', session['admin_user'], 'Autorizado')
        )
        conn.commit()
        print(f"AUDITORIA: Apertura manual exitosa del laboratorio '{laboratorio['nombre']}' por {session['admin_user']}")
    except Exception as e:
        print(f"Error al registrar acceso manual: {e}")
        conn.rollback()
        return jsonify({"error": f"Error al registrar acceso manual: {e}"}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": f"Comando de apertura enviado para {laboratorio['nombre']}"}), 200

### APIs para Gestión de Usuarios RFID ###

@app.route('/api/usuarios_rfid', methods=['GET'])
@login_required
def get_usuarios_rfid():
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM usuarios_rfid")
        usuarios = cursor.fetchall()
        for user in usuarios:
            # Manejar hora_desde
            if isinstance(user['hora_desde'], time):
                user['hora_desde'] = user['hora_desde'].strftime('%H:%M')
            elif isinstance(user['hora_desde'], timedelta):
                total_seconds = user['hora_desde'].total_seconds()
                # Si el timedelta representa una duración menor a 24 horas, lo formateamos como HH:MM
                if 0 <= total_seconds < 24 * 3600:
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    user['hora_desde'] = f"{hours:02d}:{minutes:02d}"
                else:
                    user['hora_desde'] = None
                    print(f"Advertencia: 'hora_desde' para usuario {user.get('id', 'N/A')} es timedelta fuera de rango (>=24h). Establecido a None.")
            elif user['hora_desde'] is not None: 
                # Si no es un objeto time, timedelta o None, se convierte a string.
                user['hora_desde'] = str(user['hora_desde'])
            # Si user['hora_desde'] ya es None, se mantiene como None.

            # Manejar hora_hasta
            if isinstance(user['hora_hasta'], time):
                user['hora_hasta'] = user['hora_hasta'].strftime('%H:%M')
            elif isinstance(user['hora_hasta'], timedelta):
                total_seconds = user['hora_hasta'].total_seconds()
                # Si el timedelta representa una duración menor a 24 horas, lo formateamos como HH:MM
                if 0 <= total_seconds < 24 * 3600:
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    user['hora_hasta'] = f"{hours:02d}:{minutes:02d}"
                else:
                    user['hora_hasta'] = None
                    print(f"Advertencia: 'hora_hasta' para usuario {user.get('id', 'N/A')} es timedelta fuera de rango (>=24h). Establecido a None.")
            elif user['hora_hasta'] is not None: 
                # Si no es un objeto time, timedelta o None, se convierte a string.
                user['hora_hasta'] = str(user['hora_hasta'])
            # Si user['hora_hasta'] ya es None, se mantiene como None.
        return jsonify(usuarios)
    except Exception as e:
        print(f"Error al obtener usuarios RFID: {e}")
        return jsonify({"error": "Error interno del servidor al obtener usuarios RFID"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/usuarios_rfid', methods=['POST'])
@login_required
@csrf.exempt
def create_usuario_rfid():
    data = request.json
    uuid           = data.get('uuid')
    nombre_persona = data.get('nombre_persona')
    autorizado     = data.get('autorizado', True)
    hora_desde     = data.get('hora_desde')
    hora_hasta     = data.get('hora_hasta')

    # ─── Validaciones básicas ─────────────────────────
    if not uuid or not nombre_persona:
        return jsonify({"error": "UUID y Nombre de Persona son obligatorios"}), 400
    if not is_valid_uuid(uuid):
        return jsonify({"error": "Formato de UUID inválido. Debe ser 12 hex."}), 400
    if len(nombre_persona) > 100:
        return jsonify({"error": "El nombre es demasiado largo."}), 400

    # ─── Validación y normalización de horas ───────────
    time_pattern = r'^\d{1,2}:\d{2}$'
    if hora_desde:
        if not re.match(time_pattern, hora_desde):
            return jsonify({"error": "Formato de 'Hora Desde' inválido. Use H:MM u HH:MM."}), 400
        hora_desde = normalize_hora(hora_desde)
    if hora_hasta:
        if not re.match(time_pattern, hora_hasta):
            return jsonify({"error": "Formato de 'Hora Hasta' inválido. Use H:MM u HH:MM."}), 400
        hora_hasta = normalize_hora(hora_hasta)

    conn = get_connection()
    if conn is None:
        return jsonify({"error": "Error de conexión a la base de datos"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO usuarios_rfid
              (uuid, nombre_persona, autorizado, hora_desde, hora_hasta, creado_en)
            VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (uuid, nombre_persona, autorizado, hora_desde, hora_hasta)
        )
        conn.commit()
        print(f"AUDITORIA: RFID '{nombre_persona}' ({uuid}) creado por {session['admin_user']}")
        return jsonify({"message": "Usuario RFID creado exitosamente"}), 201

    except MySQLC_Error as err:
        conn.rollback()
        if err.errno == 1062:
            return jsonify({"error": "El UUID ya existe. Usá otro."}), 409
        return jsonify({"error": str(err)}), 500

    finally:
        cursor.close()
        conn.close()
@app.route('/api/usuarios_rfid/<int:id>', methods=['PUT'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def update_usuario_rfid(id):
    data = request.json
    uuid = data.get('uuid')
    nombre_persona = data.get('nombre_persona')
    autorizado = data.get('autorizado', True)
    hora_desde = data.get('hora_desde')
    hora_hasta = data.get('hora_hasta')

    # --- Validación de Entradas ---
    if not uuid or not nombre_persona:
        return jsonify({"error": "UUID y Nombre de Persona son obligatorios"}), 400
    if not is_valid_uuid(uuid):
        return jsonify({"error": "El formato del UUID es inválido. Debe ser de 12 caracteres hexadecimales."}), 400
    if len(nombre_persona) > 100:
        return jsonify({"error": "El nombre de la persona es demasiado largo."}), 400
    if hora_desde and not re.match(r'^\d{2}:\d{2}$', hora_desde):
        return jsonify({"error": "Formato de 'Hora Desde' inválido. Use HH:MM."}), 400
    if hora_hasta and not re.match(r'^\d{2}:\d{2}$', hora_hasta):
        return jsonify({"error": "Formato de 'Hora Hasta' inválido. Use HH:MM."}), 400

    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios_rfid SET uuid=%s, nombre_persona=%s, autorizado=%s, hora_desde=%s, hora_hasta=%s WHERE id=%s",
            (uuid, nombre_persona, autorizado, hora_desde, hora_hasta, id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Usuario RFID no encontrado"}), 404
        print(f"AUDITORIA: Usuario RFID ID {id} (UUID: {uuid}) actualizado por {session['admin_user']}")
        return jsonify({"message": "Usuario RFID actualizado exitosamente"}), 200
    except MySQLC_Error as err:
        conn.rollback()
        if err.errno == 1062:
            return jsonify({"error": "El UUID ya existe. Por favor, usa uno diferente."}), 409
        print(f"Error al actualizar usuario RFID: {err}")
        return jsonify({"error": str(err)}), 500
    except Exception as e:
        conn.rollback()
        print(f"Error general al actualizar usuario RFID: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/usuarios_rfid/<int:id>', methods=['DELETE'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def delete_usuario_rfid(id):
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM usuarios_rfid WHERE id=%s", (id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Usuario RFID no encontrado"}), 404
        print(f"AUDITORIA: Usuario RFID ID {id} eliminado por {session['admin_user']}")
        return jsonify({"message": "Usuario RFID eliminado exitosamente"}), 200
    except Exception as e:
        conn.rollback()
        print(f"Error al eliminar usuario RFID: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

### APIs para Gestión de Administradores ###
@app.route('/api/admins', methods=['GET'])
@login_required
def get_admins():
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        # No retornar hashed_password por seguridad
        # Asumiendo que 'role' es una nueva columna en la tabla 'admins'
        cursor.execute("SELECT id, username, creado_en, role FROM admins")
        admins = cursor.fetchall()
        return jsonify(admins)
    except Exception as e:
        print(f"Error al obtener administradores: {e}")
        return jsonify({"error": "Error interno del servidor al obtener administradores"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admins', methods=['POST'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def create_admin():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'admin') # Rol por defecto 'admin'

    # --- Validación de Entradas ---
    if not username or not password:
        return jsonify({"error": "Nombre de usuario y contraseña son obligatorios"}), 400
    if len(username) > 50:
        return jsonify({"error": "El nombre de usuario es demasiado largo."}), 400
    if len(password) < 8: # Mínimo de 8 caracteres para la contraseña
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres."}), 400
    if role not in ['admin', 'super_admin']: # Ejemplo de roles válidos
        return jsonify({"error": "Rol inválido."}), 400


    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    try:
        # Incluir 'role' en la inserción
        cursor.execute("INSERT INTO admins (username, hashed_password, creado_en, role) VALUES (%s, %s, NOW(), %s)",
                       (username, hashed_password, role))
        conn.commit()
        print(f"AUDITORIA: Administrador '{username}' (Rol: {role}) creado por {session['admin_user']}")
        return jsonify({"message": "Administrador creado exitosamente"}), 201
    except MySQLC_Error as err:
        conn.rollback()
        if err.errno == 1062:
            return jsonify({"error": "El nombre de usuario ya existe."}), 409
        print(f"Error al crear administrador: {err}")
        return jsonify({"error": str(err)}), 500
    except Exception as e:
        conn.rollback()
        print(f"Error general al crear administrador: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admins/<int:id>', methods=['PUT'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def update_admin(id):
    data = request.json
    username = data.get('username')
    password = data.get('password') # Opcional
    role = data.get('role') # Nuevo: Permitir actualizar el rol

    # --- Validación de Entradas ---
    if not username:
        return jsonify({"error": "Nombre de usuario es obligatorio"}), 400
    if len(username) > 50:
        return jsonify({"error": "El nombre de usuario es demasiado largo."}), 400
    if password and len(password) < 8:
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres."}), 400
    if role and role not in ['admin', 'super_admin']:
        return jsonify({"error": "Rol inválido."}), 400
    
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor()
    
    try:
        update_fields = []
        params = []

        if username:
            update_fields.append("username=%s")
            params.append(username)
        if password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            update_fields.append("hashed_password=%s")
            params.append(hashed_password)
        if role: # Actualizar rol si se proporciona
            update_fields.append("role=%s")
            params.append(role)

        if not update_fields:
            return jsonify({"error": "No se proporcionaron campos para actualizar."}), 400

        query = f"UPDATE admins SET {', '.join(update_fields)} WHERE id=%s"
        params.append(id)

        cursor.execute(query, tuple(params))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Administrador no encontrado"}), 404
        print(f"AUDITORIA: Administrador ID {id} actualizado por {session['admin_user']}")
        return jsonify({"message": "Administrador actualizado exitosamente"}), 200
    except MySQLC_Error as err:
        conn.rollback()
        if err.errno == 1062:
            return jsonify({"error": "El nombre de usuario ya existe."}), 409
        print(f"Error al actualizar administrador: {err}")
        return jsonify({"error": str(err)}), 500
    except Exception as e:
        conn.rollback()
        print(f"Error general al actualizar administrador: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admins/<int:id>', methods=['DELETE'])
@login_required
@csrf.exempt # CSRF handled by Flask-WTF forms, but for API, we might handle it differently or exempt if no form
def delete_admin(id):
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    
    # Verificar si el admin que se intenta eliminar es el actualmente logueado
    cursor.execute("SELECT username FROM admins WHERE id = %s", (id,))
    admin_to_delete = cursor.fetchone()
    if admin_to_delete and admin_to_delete['username'] == session['admin_user']:
        cursor.close()
        conn.close()
        return jsonify({"error": "No puedes eliminar tu propia cuenta de administrador."}), 403

    try:
        cursor.execute("DELETE FROM admins WHERE id=%s", (id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Administrador no encontrado"}), 404
        print(f"AUDITORIA: Administrador ID {id} eliminado por {session['admin_user']}")
        return jsonify({"message": "Administrador eliminado exitosamente"}), 200
    except Exception as e:
        conn.rollback()
        print(f"Error al eliminar administrador: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

### APIs para Registros de Acceso (Ampliadas) ###

@app.route('/api/registros_acceso', methods=['GET'])
@login_required
def get_registros_acceso():
    desde = request.args.get('desde')
    hasta = request.args.get('hasta')
    laboratorio_id = request.args.get('laboratorio_id', type=int)
    tipo_acceso = request.args.get('tipo_acceso')
    resultado = request.args.get('resultado')

    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT ra.*, l.nombre as laboratorio_nombre, ur.nombre_persona as rfid_persona_nombre
        FROM registros_acceso ra
        JOIN laboratorios l ON ra.laboratorio_id = l.id
        LEFT JOIN usuarios_rfid ur ON ra.uuid_rfid = ur.uuid
        WHERE 1=1
    """
    params = []

    if desde:
        query += " AND ra.creado_en >= %s"
        params.append(desde + " 00:00:00")
    if hasta:
        query += " AND ra.creado_en <= %s"
        params.append(hasta + " 23:59:59")
    if laboratorio_id:
        query += " AND ra.laboratorio_id = %s"
        params.append(laboratorio_id)
    if tipo_acceso:
        query += " AND ra.tipo_acceso = %s"
        params.append(tipo_acceso)
    if resultado:
        query += " AND ra.resultado = %s"
        params.append(resultado)

    query += " ORDER BY ra.creado_en DESC"

    try:
        cursor.execute(query, tuple(params))
        registros = cursor.fetchall()
        for registro in registros:
            if isinstance(registro['creado_en'], datetime):
                registro['creado_en'] = registro['creado_en'].isoformat()
            elif isinstance(registro['creado_en'], date):
                registro['creado_en'] = registro['creado_en'].isoformat()
            elif isinstance(registro['creado_en'], timedelta):
                registro['creado_en'] = str(registro['creado_en'])
            elif registro['creado_en'] is None:
                registro['creado_en'] = None
        return jsonify(registros)
    except Exception as e:
        print(f"Error al obtener registros de acceso: {e}")
        return jsonify({"error": "Error interno del servidor al obtener registros"}), 500
    finally:
        cursor.close()
        conn.close()

# NUEVA API: Obtener el último UUID de RFID de los registros de acceso
@app.route('/api/registros_acceso/latest_uuid', methods=['GET'])
@login_required
def get_latest_rfid_uuid():
    last_id = request.args.get('last_id', type=int)
    conn = get_connection()
    if conn is None:
        return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT uuid_rfid, id FROM registros_acceso WHERE uuid_rfid IS NOT NULL"
        params = []
        if last_id:
            query += " AND id > %s"
            params.append(last_id)
        query += " ORDER BY creado_en DESC, id DESC LIMIT 1" # Order by created_at then id to ensure latest
        cursor.execute(query, tuple(params))
        latest_uuid_entry = cursor.fetchone()
        if latest_uuid_entry:
            return jsonify({"uuid": latest_uuid_entry['uuid_rfid'], "id": latest_uuid_entry['id']})
        return jsonify({"message": "No new RFID UUID found"}), 200
    except Exception as e:
        print(f"Error al obtener el último UUID RFID: {e}")
        return jsonify({"error": "Error interno del servidor al obtener el último UUID RFID"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/registros_acceso/exportar', methods=['GET'])
@login_required
def export_registros_acceso():
    conn = get_connection()
    if conn is None: return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT ra.id, l.nombre as laboratorio, ra.tipo_acceso, ra.usuario_admin, ra.uuid_rfid, ra.resultado, ra.creado_en
            FROM registros_acceso ra
            JOIN laboratorios l ON ra.laboratorio_id = l.id
            ORDER BY ra.creado_en DESC
        """)
        registros = cursor.fetchall()

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID Registro', 'Laboratorio', 'Tipo Acceso', 'Usuario Admin', 'UUID RFID', 'Resultado', 'Fecha y Hora'])

        for r in registros:
            uuid_rfid_val = r.get('uuid_rfid', 'N/A')
            usuario_admin_val = r.get('usuario_admin', 'N/A')
            cw.writerow([r['id'], r['laboratorio'], r['tipo_acceso'], usuario_admin_val, uuid_rfid_val, r['resultado'], r['creado_en'].strftime('%Y-%m-%d %H:%M:%S')])

        output = si.getvalue()
        response = Response(output, mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=registros_acceso_etec.csv'
        return response
    except Exception as e:
        print(f"Error al exportar registros: {e}")
        return jsonify({"error": "Error interno del servidor al exportar registros"}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

### API de Estadísticas (Ampliadas) ###

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    conn = get_connection()
    if conn is None:
        return jsonify({"error": "Error de conexión a la base de datos"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT
                ra.tipo_acceso,
                ra.resultado,
                COUNT(*) AS total_accesos,
                DATE_FORMAT(ra.creado_en, '%Y-%m-%d') AS fecha,
                DATE_FORMAT(ra.creado_en, '%H') AS hora,
                l.nombre AS laboratorio_nombre
            FROM registros_acceso ra
            JOIN laboratorios l ON ra.laboratorio_id = l.id
            GROUP BY ra.tipo_acceso, ra.resultado, fecha, hora, laboratorio_nombre
            ORDER BY fecha, hora
        """)
        raw_stats = cursor.fetchall()
        cursor.close()
        conn.close()

        # Armado de las estructuras de respuesta
        total_accesos = sum(s['total_accesos'] for s in raw_stats)
        accesos_por_laboratorio = {}
        accesos_por_dia = {}
        accesos_por_hora = {}
        accesos_por_tipo = {}
        accesos_por_resultado = {}

        for s in raw_stats:
            lab_name = s['laboratorio_nombre']
            fecha = s['fecha']
            hora = s['hora']
            tipo = s['tipo_acceso']
            resultado = s['resultado']
            count = s['total_accesos']

            accesos_por_laboratorio[lab_name] = accesos_por_laboratorio.get(lab_name, 0) + count
            accesos_por_dia[fecha] = accesos_por_dia.get(fecha, 0) + count
            accesos_por_hora[hora] = accesos_por_hora.get(hora, 0) + count
            accesos_por_tipo[tipo] = accesos_por_tipo.get(tipo, 0) + count
            accesos_por_resultado[resultado] = accesos_por_resultado.get(resultado, 0) + count

        return jsonify({
            "total_accesos": total_accesos,
            "accesos_por_laboratorio": accesos_por_laboratorio,
            "accesos_por_dia": accesos_por_dia,
            "accesos_por_hora": accesos_por_hora,
            "accesos_por_tipo": accesos_por_tipo,
            "accesos_por_resultado": accesos_por_resultado
        })
    except Exception as e:
        print(f"Error al obtener estadísticas: {e}")
        return jsonify({"error": "Error interno del servidor al obtener estadísticas"}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

### API para Generar Reporte de Auditoría PDF ###
@app.route('/api/audit_report_pdf', methods=['GET'])
@login_required
def generate_audit_report_pdf():
    # Obtener parámetros de filtro de fecha
    desde_str = request.args.get('desde')
    hasta_str = request.args.get('hasta')

    conn = get_connection()
    if conn is None:
        return jsonify({"error": "Error de conexión a la base de datos"}), 500

    
    # --- Obtener Estadísticas para el Resumen (filtradas por fechas) ---
    stats_query = """
        SELECT
            ra.tipo_acceso,
            ra.resultado,
            COUNT(ra.id) as total_accesos
        FROM registros_acceso ra
        WHERE 1=1
    """
    stats_params = []
    if desde_str:
        stats_query += " AND ra.creado_en >= %s"
        stats_params.append(desde_str + " 00:00:00")
    if hasta_str:
        stats_query += " AND ra.creado_en <= %s"
        stats_params.append(hasta_str + " 23:59:59")
    stats_query += " GROUP BY ra.tipo_acceso, ra.resultado"

    cursor_stats = conn.cursor(dictionary=True)
    try:
        cursor_stats.execute(stats_query, tuple(stats_params))
        raw_stats = cursor_stats.fetchall()
    except Exception as e:
        print(f"Error al obtener estadísticas para PDF: {e}")
        return jsonify({"error": f"Error al obtener estadísticas para el reporte PDF: {e}"}), 500
    finally:
        cursor_stats.close() # Cerrar el cursor de estadísticas

    total_accesos_stats = sum(s['total_accesos'] for s in raw_stats)
    accesos_por_tipo_stats = {}
    accesos_por_resultado_stats = {}

    for s in raw_stats:
        tipo = s['tipo_acceso']
        resultado = s['resultado']
        count = s['total_accesos']
        accesos_por_tipo_stats[tipo] = accesos_por_tipo_stats.get(tipo, 0) + count
        accesos_por_resultado_stats[resultado] = accesos_por_resultado_stats.get(resultado, 0) + count

    # --- Obtener Registros Detallados (filtrados por fechas) ---
    cursor_logs = conn.cursor(dictionary=True) # Nuevo cursor para los logs
    query_logs = """
        SELECT ra.creado_en, l.nombre as laboratorio, ra.tipo_acceso,
               COALESCE(ra.usuario_admin, ur.nombre_persona, ra.uuid_rfid, 'N/A') as responsable,
               ra.resultado, ra.uuid_rfid
        FROM registros_acceso ra
        JOIN laboratorios l ON ra.laboratorio_id = l.id
        LEFT JOIN usuarios_rfid ur ON ra.uuid_rfid = ur.uuid
        WHERE 1=1
    """
    params_logs = []
    if desde_str:
        query_logs += " AND ra.creado_en >= %s"
        params_logs.append(desde_str + " 00:00:00")
    if hasta_str:
        query_logs += " AND ra.creado_en <= %s"
        params_logs.append(hasta_str + " 23:59:59")
    query_logs += " ORDER BY ra.creado_en DESC"

    try:
        cursor_logs.execute(query_logs, tuple(params_logs))
        logs = cursor_logs.fetchall()
        cursor_logs.close()
        conn.close()

        # Crear el documento PDF en memoria
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                                 rightMargin=40, leftMargin=40,
                                 topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()

        # Estilos personalizados
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['h1'],
            fontSize=22,
            leading=26,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['h2'],
            fontSize=14,
            leading=18,
            alignment=TA_CENTER,
            spaceAfter=15,
            fontName='Helvetica-Bold'
        )
        date_style = ParagraphStyle(
            'DateStyle',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_RIGHT,
            spaceAfter=5
        )
        intro_style = ParagraphStyle(
            'IntroStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            alignment=TA_LEFT,
            spaceAfter=20
        )
        section_title_style = ParagraphStyle( # Estilo para títulos de sección como "Resumen"
            'SectionTitleStyle',
            parent=styles['h3'],
            fontSize=12,
            leading=14,
            alignment=TA_LEFT,
            spaceAfter=10,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor('#1a202c')
        )
        list_item_style = ParagraphStyle( # Estilo para ítems de lista en el resumen
            'ListItemStyle',
            parent=styles['Normal'],
            fontSize=10,
            leading=12,
            alignment=TA_LEFT,
            spaceAfter=3
        )
        table_header_style = ParagraphStyle(
            'TableHeaderStyle',
            parent=styles['Normal'],
            fontSize=9,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            textColor=colors.whitesmoke
        )
        table_cell_style = ParagraphStyle(
            'TableCellStyle',
            parent=styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
        )
        footer_style = ParagraphStyle(
            'FooterStyle',
            parent=styles['Normal'],
            fontSize=8,
            alignment=TA_CENTER,
            spaceBefore=20,
            textColor=colors.grey
        )

        elements = []

        # Logo de la ETec
        logo_path = os.path.join(ASSETS_FOLDER, 'logoetec.png')
        if os.path.exists(logo_path):
            # Reducir el tamaño del logo para que sea menos dominante
            img = Image(logo_path, width=0.8*inch, height=0.8*inch)
            img.hAlign = 'CENTER'
            elements.append(img)
            elements.append(Spacer(1, 0.1 * inch))
        else:
            print(f"Advertencia: Logo no encontrado en {logo_path}")
            elements.append(Paragraph("<b>[Logo ETec no encontrado]</b>", styles['Normal']))
            elements.append(Spacer(1, 0.1 * inch))


        # Título del reporte
        elements.append(Paragraph("Reporte de Auditoría de Accesos", title_style))
        elements.append(Paragraph("Sistema de Cerraduras Inteligentes - ETec", subtitle_style))
        
        elements.append(Paragraph(f"<b>Fecha de Generación:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", date_style))
        if desde_str and hasta_str:
            elements.append(Paragraph(f"<b>Periodo:</b> Del {desde_str} al {hasta_str}", date_style))
        elif desde_str:
            elements.append(Paragraph(f"<b>Periodo:</b> Desde el {desde_str}", date_style))
        elif hasta_str:
            elements.append(Paragraph(f"<b>Periodo:</b> Hasta el {hasta_str}", date_style))
        
        elements.append(Spacer(1, 0.2 * inch))

        # Párrafo introductorio
        elements.append(Paragraph(
            "Este informe detalla los registros de acceso a los laboratorios de la Escuela Técnica de la Universidad de Mendoza. Incluye tanto aperturas manuales realizadas por administradores como intentos de acceso mediante tarjetas RFID, con indicación del resultado (exitoso o fallido).",
            intro_style
        ))
        elements.append(Spacer(1, 0.2 * inch))

        # --- Sección de Resumen de Estadísticas ---
        elements.append(Paragraph("Resumen de Estadísticas", section_title_style))
        elements.append(Paragraph(f"Total de Accesos en el Periodo: <b>{total_accesos_stats}</b>", list_item_style))
        elements.append(Spacer(1, 0.1 * inch))

        if accesos_por_tipo_stats:
            elements.append(Paragraph("Accesos por Tipo:", list_item_style))
            for tipo, count in accesos_por_tipo_stats.items():
                elements.append(Paragraph(f"- {tipo.replace('_', ' ').title()}: {count}", list_item_style))
            elements.append(Spacer(1, 0.1 * inch))

        if accesos_por_resultado_stats:
            elements.append(Paragraph("Accesos por Resultado:", list_item_style))
            for resultado, count in accesos_por_resultado_stats.items():
                color_hex = "#008000" if resultado == 'exitoso' else "#FF0000" if resultado == 'fallido' else "#808080"
                elements.append(Paragraph(f'- <font color="{color_hex}">{resultado.title()}</font>: {count}', list_item_style))
            elements.append(Spacer(1, 0.2 * inch))
        
        elements.append(Paragraph("Registros Detallados:", section_title_style))
        elements.append(Spacer(1, 0.1 * inch))

        # --- Tabla de registros detallados ---
        table_data = [
            [Paragraph('Fecha y Hora', table_header_style),
             Paragraph('Laboratorio', table_header_style),
             Paragraph('Tipo Acceso', table_header_style),
             Paragraph('Responsable', table_header_style),
             Paragraph('Resultado', table_header_style)]
        ]
        
        for log in logs:
            # Formato de la fecha
            fecha_hora_str = log['creado_en'].strftime('%Y-%m-%d %H:%M:%S') if log['creado_en'] else 'N/A'
            
            # Formato del tipo de acceso
            tipo_acceso_display = log['tipo_acceso'].replace('_', ' ').title()

            # Formato del responsable (COALESCE ya lo maneja en SQL)
            responsable_display = log['responsable']

            # Formato del resultado con colores
            resultado_display = log['resultado'].title()
            if log['resultado'] == 'exitoso':
                resultado_paragraph = Paragraph(f'<font color="#008000">{resultado_display}</font>', table_cell_style)
            elif log['resultado'] == 'fallido':
                resultado_paragraph = Paragraph(f'<font color="#FF0000">{resultado_display}</font>', table_cell_style)
            else:
                resultado_paragraph = Paragraph(resultado_display, table_cell_style) # Default color

            table_data.append([
                Paragraph(fecha_hora_str, table_cell_style),
                Paragraph(log['laboratorio'], table_cell_style),
                Paragraph(tipo_acceso_display, table_cell_style),
                Paragraph(responsable_display, table_cell_style),
                resultado_paragraph
            ])

        # Definir anchos de columna para un layout responsivo
        # Ajustar según necesidad para que quepan bien los datos
        col_widths = [1.5*inch, 1.5*inch, 1.3*inch, 2.0*inch, 1.0*inch]
        table = Table(table_data, colWidths=col_widths)

        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a202c')), # Fondo oscuro para el encabezado
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Aplicar fondo alternado para las filas de datos
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')), # Bordes de grilla suaves
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#9ca3af')), # Borde exterior de la tabla
            ('LEFTPADDING', (0,0), (-1,-1), 2),
            ('RIGHTPADDING', (0,0), (-1,-1), 2),
            ('TOPPADDING', (0,1), (-1,-1), 5),
            ('BOTTOMPADDING', (0,1), (-1,-1), 5),
        ])

        # Alternar colores de fila (para mejor legibilidad)
        for i in range(1, len(table_data)):
            if i % 2 == 0:
                table_style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#ffffff')) # Blanco
            else:
                table_style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f0f2f5')) # Gris claro

        table.setStyle(table_style)
        elements.append(table)
        elements.append(Spacer(1, 0.4 * inch))

        # Pie de página
        elements.append(Paragraph("Universidad de Mendoza - Escuela Técnica (ETec)", footer_style))
        elements.append(Paragraph("Sistema de Cerraduras Inteligentes - Reporte Confidencial", footer_style))


        doc.build(elements)
        buffer.seek(0)

        return Response(buffer.getvalue(), mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=Reporte_Auditoria_ETec.pdf'})

    except Exception as e:
        print(f"Error al generar el reporte PDF: {e}")
        return jsonify({"error": f"Error al generar el reporte de auditoría: {e}"}), 500
    finally:
        if conn and conn.is_connected():
            cursor_logs.close() # Asegurar que se cierra el cursor que se usa al final.
            conn.close()


if __name__ == '__main__':
    # Para producción, no usar app.run(). Usar un servidor WSGI como Gunicorn.
    # Para HTTPS en producción, usar un proxy inverso como Nginx/Apache con certificados SSL/TLS.
    app.run(debug=True, host='0.0.0.0')
