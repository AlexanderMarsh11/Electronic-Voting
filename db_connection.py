import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",                
    password="Password123",   
    database="electronic_voting"
)

cursor = db.cursor()
print("Connected to MySQL database!")