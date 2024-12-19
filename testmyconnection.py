import pymysql

try:
    conn = pymysql.connect(
        host="127.0.0.1",
        user="root",
        password="MySQL@123",
        database="my_project",
        port=3306
    )
    print("Connected to MySQL!")
    conn.close()
except Exception as e:
    print("Failed to connect:", e)
