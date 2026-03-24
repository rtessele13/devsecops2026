"""
Ricardo Tessele
OK S — Spoofing: Possibilidade de login sem senha via SQL Injection.
OK T — Tampering: Manipulação de dados por queries inseguras.
R — Repudiation: Falta de logs adequados para rastreamento.
OK I — Information Disclosure: Vazamento de dados via debug e senhas armazenadas em texto puro.
D — Denial of Service: Falta de rate limiting que permite brute force e sobrecarga.
OK E — Elevation of Privilege: SQL Injection permite escalar privilégios ou obter dados sensíveis.
"""

from flask import Flask, request, render_template, session, url_for, redirect
from werkzeug.security import check_password_hash

import sqlite3

app = Flask(__name__)

# Resolvemos através de um cofre de senhas / gerenciador de segredos
app.secret_key = b'1234'

# Simulação de um banco de dados inseguro
def get_db_connection():
    conn = sqlite3.connect('database.db')
    return conn

@app.route("/", methods=['GET'])
def index():
    return render_template('index.html')

@app.route("/welcome", methods=['GET'])
def welcome():

    if 'username' in session:
        username = session.pop('username')
        return render_template('welcome.html', username=username)

    return render_template('error.html')
    

@app.route("/login", methods=['GET'])
def login_page():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('passwd') 
    
    print(f"QUERY PARAMETERS: username={username}")

    conn = get_db_connection()
    query = f"SELECT passwd FROM users where username = ?"
    stored_passwd = conn.execute(query, (username,)).fetchone()
    if stored_passwd == None:
        return "Usuário ou senha incorretos", 401

    if check_password_hash(stored_passwd[0], password):
        session['username'] = username
        return redirect(url_for('welcome'))
    return "Usuário ou senha incorretos", 401

if __name__ == '__main__':
    app.run(debug=True)