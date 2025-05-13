from flask import Flask, render_template, request, redirect, session, jsonify, make_response
import bcrypt
from datetime import datetime, timedelta
from utils.db import get_connection
from flask_cors import CORS
from weasyprint import HTML
import paho.mqtt.publish as publish

app = Flask(__name__)
app.secret_key = 'superclave'
CORS(app)

### LOGIN ###
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admins WHERE usuario = %s", (usuario,))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()
        if admin and bcrypt.checkpw(password.encode(), admin['hash_password'].encode()):
            session['admin'] = usuario
            registrar_accion(f"Inicio de sesión", usuario)
            return redirect('/dashboard')
        return render_template('login.html', error=True)
    return render_template('login.html')

### DASHBOARD ###
@app.route('/dashboard')
def dashboard():
    if 'admin' not in session:
        return redirect('/')
    return render_template('dashboard.html')

### USUARIOS ###
@app.route('/usuarios')
def usuarios():
    if 'admin' not in session:
        return redirect('/')
    return render_template('usuarios.html')

### API: Obtener todos los usuarios ###
@app.route('/api/usuarios')
def api_usuarios():
    laboratorio_id = request.args.get('laboratorio_id')
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    if laboratorio_id:
        cursor.execute("SELECT * FROM usuarios WHERE laboratorio_id = %s", (laboratorio_id,))
    else:
        cursor.execute("SELECT * FROM usuarios")
    usuarios = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(usuarios)


### API: Crear usuario ###
@app.route('/api/usuarios', methods=['POST'])
def crear_usuario():
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO usuarios (uid, nombre, estado, creado_en)
        VALUES (%s, %s, %s, NOW())
    """, (data['uid'], data['nombre'], data['estado']))
    registrar_accion(f"Creación de usuario: {data['uid']} - {data['nombre']}", session['admin'])
    conn.commit()
    cursor.close()
    conn.close()
    return '', 204



### API: Editar usuario existente ###
@app.route('/api/usuarios/<int:id>', methods=['PUT'])
def editar_usuario(id):
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE usuarios
        SET uid=%s, nombre=%s, estado=%s
        WHERE id=%s
    """, (data['uid'], data['nombre'], data['estado'], id))
    registrar_accion(f"Edición de usuario ID: {id} -> {data['uid']} - {data['nombre']}", session['admin'])
    conn.commit()
    cursor.close()
    conn.close()
    return '', 204



### API: Eliminar usuario ###
@app.route('/api/usuarios/<int:id>', methods=['DELETE'])
def eliminar_usuario(id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id=%s", (id,))
    registrar_accion(f"Eliminación de usuario ID: {id}", session['admin'], None)
    conn.commit()
    cursor.close()
    conn.close()
    return '', 204


### API: Obtener logs con filtro ###
@app.route('/api/logs')
def obtener_logs():
    desde = request.args.get('desde')
    hasta = request.args.get('hasta')
    laboratorio_id = request.args.get('laboratorio_id')

    if not (desde and hasta):
        return jsonify([])

    desde_full = f"{desde} 00:00:00"
    hasta_full = f"{hasta} 23:59:59"

    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    if laboratorio_id:
        cur.execute("""
            SELECT l.id, l.uid,
                   COALESCE(u.nombre, 'desconocido') AS nombre,
                   l.fecha_hora, l.estado
            FROM logs_accesos l
            LEFT JOIN usuarios u ON u.uid = l.uid
            WHERE l.fecha_hora BETWEEN %s AND %s AND l.laboratorio_id = %s
            ORDER BY l.fecha_hora
        """, (desde_full, hasta_full, laboratorio_id))
    else:
        cur.execute("""
            SELECT l.id, l.uid,
                   COALESCE(u.nombre, 'desconocido') AS nombre,
                   l.fecha_hora, l.estado
            FROM logs_accesos l
            LEFT JOIN usuarios u ON u.uid = l.uid
            WHERE l.fecha_hora BETWEEN %s AND %s
            ORDER BY l.fecha_hora
        """, (desde_full, hasta_full))

    datos = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(datos)

### API: Exportar logs ###
@app.route('/api/logs/exportar')
def exportar_logs():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs_accesos")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    response = app.response_class(
        response='\n'.join([','.join(map(str, row)) for row in logs]),
        mimetype='text/csv'
    )
    response.headers['Content-Disposition'] = 'attachment; filename=logs.csv'
    return response

### API: Exportar auditoría en PDF (últimos 15 días) ###
@app.route('/auditoria/pdf')
def exportar_auditoria_pdf():
    fecha_limite = datetime.now() - timedelta(days=15)
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT * FROM auditoria
        WHERE fecha >= %s
        ORDER BY fecha DESC
    """, (fecha_limite,))
    logs = cur.fetchall()
    cur.close(); conn.close()

    rendered = render_template("auditoria_pdf.html", logs=logs, now=datetime.now())
    pdf = HTML(string=rendered, base_url=request.base_url).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=auditoria.pdf'
    return response

### API: Estadísticas para dashboard ###
@app.route('/api/stats')
def stats():
    laboratorio_id = request.args.get('laboratorio_id')
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    if laboratorio_id:
        cursor.execute("""
            SELECT l.id, l.uid, l.fecha_hora AS creado_en,
                   COALESCE(u.nombre, 'desconocido') AS nombre,
                   l.estado
            FROM logs_accesos l
            LEFT JOIN usuarios u ON l.uid = u.uid
            WHERE l.laboratorio_id = %s
            ORDER BY l.fecha_hora
        """, (laboratorio_id,))
    else:
        cursor.execute("""
            SELECT l.id, l.uid, l.fecha_hora AS creado_en,
                   COALESCE(u.nombre, 'desconocido') AS nombre,
                   l.estado
            FROM logs_accesos l
            LEFT JOIN usuarios u ON l.uid = u.uid
            ORDER BY l.fecha_hora
        """)

    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    

    total = len(logs)
    validos = sum(1 for l in logs if l['estado'] == 'correcto')
    invalidos = total - validos
    por_uid = {}
    por_dia = {}
    por_hora = {}
    intervalos = []

    last_ts = None
    for l in logs:
        uid = l['uid']
        fecha = l['creado_en'].strftime('%Y-%m-%d')
        hora = l['creado_en'].strftime('%H')
        ts = l['creado_en'].timestamp()

        por_uid[uid] = por_uid.get(uid, 0) + 1
        por_dia[fecha] = por_dia.get(fecha, 0) + 1
        por_hora[hora] = por_hora.get(hora, 0) + 1

        if last_ts:
            intervalos.append(ts - last_ts)
        last_ts = ts

    avg_interval = int(sum(intervalos) / len(intervalos)) if intervalos else 0

    return jsonify({
        "total": total,
        "validos": validos,
        "invalidos": invalidos,
        "ultimos_uids": por_uid,
        "por_dia": por_dia,
        "por_hora": por_hora,
        "intervalo_promedio_segundos": avg_interval,
        "ultimo_acceso": logs[-1]['creado_en'].strftime('%Y-%m-%d %H:%M:%S') if logs else None
    })

@app.route('/api/logs/latest')
def ultimo_log():
    after = request.args.get('after', type=int)
    conn  = get_connection(); cur = conn.cursor(dictionary=True)
    if after:
        cur.execute("SELECT * FROM logs_accesos WHERE id > %s ORDER BY id DESC LIMIT 1",(after,))
    else:
        cur.execute("SELECT * FROM logs_accesos ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    cur.close(); conn.close()
    return jsonify(row if row else {})

@app.route('/logs')
def logs():
    if 'admin' not in session:
        return redirect('/')
    return render_template('logs.html')

@app.route('/logout')
def logout():
    registrar_accion("Cierre de sesión", session.get('admin', 'desconocido'))
    session.pop('admin', None)
    return render_template('login.html')

# FUNCION PARA AUDITORÍA

def registrar_accion(accion, usuario_admin, laboratorio_id=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO auditoria (accion, usuario_admin, fecha, laboratorio_id)
        VALUES (%s, %s, NOW(), %s)
    """, (accion, usuario_admin, laboratorio_id))
    conn.commit()
    cursor.close()
    conn.close()


@app.route('/auditoria')
def auditoria():
    if 'admin' not in session:
        return redirect('/')
    return render_template('auditoria.html')

@app.route('/api/auditoria')
def api_auditoria():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM auditoria ORDER BY fecha DESC")
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)

@app.route('/estadisticas')
def estadisticas():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Accesos válidos vs inválidos
    cursor.execute("SELECT estado, COUNT(*) as cantidad FROM logs_accesos GROUP BY estado")
    estado_data = cursor.fetchall()

    # Top 5 UIDs
    cursor.execute("SELECT uid, COUNT(*) as cantidad FROM logs_accesos GROUP BY uid ORDER BY cantidad DESC LIMIT 5")
    top_uids = cursor.fetchall()

    # Accesos últimos 7 días
    cursor.execute("""
        SELECT DATE(fecha_hora) as dia, COUNT(*) as cantidad 
        FROM logs_accesos 
        GROUP BY dia 
        ORDER BY dia DESC 
        LIMIT 7
    """)
    por_dia = cursor.fetchall()

    # Heatmap: día y hora
    cursor.execute("""
        SELECT 
            DAYNAME(fecha_hora) AS dia_semana, 
            HOUR(fecha_hora) AS hora, 
            COUNT(*) AS cantidad
        FROM logs_accesos
        GROUP BY dia_semana, hora
    """)
    heatmap_data = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("estadisticas.html", 
        estado_data=estado_data, 
        top_uids=top_uids, 
        por_dia=por_dia,
        heatmap_data=heatmap_data
    )

@app.route('/api/laboratorios')
def get_laboratorios():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM laboratorios")
    data = cursor.fetchall()
    cursor.close(); conn.close()
    return jsonify(data)


@app.route('/abrir_manual', methods=['POST'])
def abrir_manual():
    if 'admin' not in session:
        return jsonify({'status': 'error', 'message': 'No autorizado'}), 403

    laboratorio_id = int(request.json.get('laboratorio_id', 1))

    # Diccionario de topics
    topics = {
        1: "cerraduras/lab1elec/open",
        2: "cerraduras/lab2elec/open",
        3: "cerraduras/lab1info/open",
        4: "cerraduras/lab2info/open"
    }

    topic = topics.get(laboratorio_id)
    if not topic:
        return jsonify({'status': 'error', 'message': 'Laboratorio no definido'}), 400

    try:
        publish.single(topic, payload="1", hostname="192.168.54.123")
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error al publicar MQTT: {e}'}), 500

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs_accesos (uid, nombre, estado, laboratorio_id)
        VALUES (%s, %s, %s, %s)
    """, ("admin_manual", "Apertura Manual", "manual", laboratorio_id))
    conn.commit()
    cursor.close()
    conn.close()

    registrar_accion("Apertura manual desde la web", session['admin'], laboratorio_id)

    return jsonify({'status': 'ok', 'message': f'Cerradura abierta en {topic}'})


if __name__ == '__main__':
    app.run(debug=True)