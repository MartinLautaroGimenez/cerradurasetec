import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host='192.168.54.123',
        user='root',
        password='casaos',
        database='control_accesos'
    )
