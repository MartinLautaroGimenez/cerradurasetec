from flask import Flask, render_template, request, redirect, session, jsonify
import bcrypt
import csv
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

### API: Obtener usuarios ###
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
    cursor.execute("INSERT INTO usuarios (uid, nombre, estado, creado_en) VALUES (%s, %s, %s, NOW())",
                   (data['uid'], data['nombre'], data['estado']))
    conn.commit()
    cursor.close()
    conn.close()
    return '', 204

### API: Editar usuario ###
@app.route('/api/usuarios/<int:id>', methods=['PUT'])
def editar_usuario(id):
    data = request.json
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET uid=%s, nombre=%s, estado=%s WHERE id=%s",
                   (data['uid'], data['nombre'], data['estado'], id))
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
@app.route('/api/logs')
def obtener_logs():
    desde = request.args.get('desde')
    hasta = request.args.get('hasta')
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM logs_accesos WHERE fecha_hora BETWEEN %s AND %s",
               (desde + " 00:00:00", hasta + " 23:59:59"))
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(logs)

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
@app.route('/api/stats')
def stats():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM logs_accesos ORDER BY creado_en")
    logs = cursor.fetchall()
    cursor.close()
    conn.close()

    total = len(logs)
    validos = sum(1 for l in logs if l['nombre'] != 'desconocido')
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

        if last_ts: intervalos.append(ts - last_ts)
        last_ts = ts

    avg_interval = int(sum(intervalos)/len(intervalos)) if intervalos else 0

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

if __name__ == '__main__':
    app.run(debug=True)
