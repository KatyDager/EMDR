from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'EMDR'

# Intialize MySQL
mysql = MySQL(app)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Create variables for easy access
        email = request.json['email']
        password = request.json['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s AND password = %s', (email, password,))
        # Fetch one record and return result
        account = cursor.fetchone()
        
        # If account exists in accounts table in out database
        if account:
            #print("buna")
            # Create session data, we can access this data in other routes
            # session['loggedin'] = True
            # session['id'] = account['id']
            # session['email'] = account['email']
            # Redirect to home page
            return jsonify({"message":"Login successful"})
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
            return msg
        return "Vezi ca trebuie token aicea"
    
    
@app.route('/register', methods=['GET', 'POST'])    
def registration():
    if request.method == 'POST':
        # Create variables for easy access
        email = request.json['email']
        password = request.json['password']
        firstname = request.json['firstname']
        lastname  = request.json['lastname']
        dateofbirth = request.json['dateofbirth']
        gender = request.json['gender']
        phonenumber  = request.json['phonenumber']
        postalcode = request.json['postalcode']
        country = request.json['country']
        
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO accounts(firstname, lastname, dateofbirth, gender, email, phonenumber, postalcode, country, password) VALUES (%s, %s,%s, %s,%s, %s,%s, %s,%s)", (firstname, lastname, dateofbirth, gender, email, phonenumber, postalcode, country, password))
        mysql.connection.commit()
        cursor.close()
        return "Registration successful"
        

if __name__ == '__main__':
    app.run()

