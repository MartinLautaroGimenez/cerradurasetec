from flask import Flask, render_template, request, redirect, session, jsonify
import bcrypt
from datetime import datetime
from utils.db import get_connection
from flask_cors import CORS

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
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
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
    conn.commit()
    cursor.close()
    conn.close()
    return '', 204

### API: Obtener logs con filtro ###
### API: Obtener logs con filtro ###
@app.route('/api/logs')
def obtener_logs():
    desde = request.args.get('desde')   # 2025-04-07
    hasta = request.args.get('hasta')   # 2025-05-07
    if not (desde and hasta):
        return jsonify([])

    # ampliamos al día completo
    desde_full = f"{desde} 00:00:00"
    hasta_full = f"{hasta} 23:59:59"

    conn = get_connection()
    cur  = conn.cursor(dictionary=True)
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

### API: Estadísticas para dashboard ###
@app.route('/api/stats')
def stats():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
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

# ---- NUEVO: último log (opcionalmente posterior a after) ----
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

# ---------- CERRAR SESIÓN ----------
@app.route('/logout')
def logout():
    session.pop('admin', None)          # borra la cookie de sesión
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)
