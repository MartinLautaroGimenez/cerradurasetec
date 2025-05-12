import bcrypt
import mysql.connector

usuario = 'tincho'
password = '1234'

hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

conn = mysql.connector.connect(
    host='192.168.54.123',
    user='root',
    password='casaos',
    database='control_accesos'
)
cursor = conn.cursor()
cursor.execute("INSERT INTO admins (usuario, hash_password) VALUES (%s, %s)", (usuario, hash))
conn.commit()
cursor.close()
conn.close()

print("✅ Admin creado correctamente.")
