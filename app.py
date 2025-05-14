from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'clave_secreta'
DATABASE = 'tareas.db'

# Conexión directa sin usar `g`
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

import sqlite3

conn = sqlite3.connect('tareas.db')
c = conn.cursor()

#c.execute("""
#CREATE TABLE IF NOT EXISTS users (
 #   id INTEGER PRIMARY KEY AUTOINCREMENT,
  #  username TEXT NOT NULL UNIQUE,
   # password_hash TEXT NOT NULL,
    #created_at DATETIME DEFAULT CURRENT_TIMESTAMP
#)
#""")

#c.execute("""
#CREATE TABLE IF NOT EXISTS tasks (
 #   id INTEGER PRIMARY KEY AUTOINCREMENT,
  #  title TEXT NOT NULL,
   # description TEXT,
    #completed BOOLEAN NOT NULL DEFAULT 0,
    #user_id INTEGER,
    #created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    #FOREIGN KEY(user_id) REFERENCES users(id)
#)
#""")
#conn.commit()
#conn.close()
#print("Base de datos creada con éxito.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return 'Usuario y contraseña son requeridos'

        password_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return 'El nombre de usuario ya está registrado.'
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return 'Credenciales inválidas'

    return render_template('login.html')

@app.route('/')
def index():
    # Verificamos si el usuario está logueado (esto puede ser redundante si ya usas `@login_required`)
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    tasks = conn.execute(
        'SELECT t.*, u.username FROM tasks t JOIN users u ON t.user_id = u.id WHERE t.user_id = ?',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return render_template('index.html', tasks=tasks)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Verificamos si el usuario está logueado
    if 'user_id' not in session:
        return redirect('/login')

    # Conexión a la base de datos
    conn = get_db_connection()

    # Mostrar las tareas del usuario
    tasks = conn.execute(
        'SELECT * FROM tasks WHERE user_id = ?',
        (session['user_id'],)
    ).fetchall()

    if request.method == 'POST':
        # Recoger los datos del formulario para crear una nueva tarea
        title = request.form['title']
        description = request.form['description']

        if not title or not description:
            return 'Por favor, ingresa título y descripción.'

        # Guardamos la nueva tarea en la base de datos
        conn.execute(
            'INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)',
            (title, description, False, session['user_id'])
        )
        conn.commit()

        return redirect('/')

    conn.close()
    return render_template('dashboard.html', tasks=tasks)


@app.route('/edit/<int:task_id>', methods=['POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect('/login')

    # Asegúrate de que los campos del formulario existan
    title = request.form.get('title')
    description = request.form.get('description')

    if not title or not description:
        return 'Por favor, ingresa título y descripción.'

    conn = get_db_connection()
    conn.execute(
        'UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?',
        (title, description, task_id, session['user_id'])
    )
    conn.commit()
    conn.close()

    return redirect('/dashboard')

@app.route('/delete/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    task = conn.execute(
        'SELECT * FROM tasks WHERE id = ? AND user_id = ?',
        (task_id, session['user_id'])
    ).fetchone()

    if not task:
        return 'Tarea no encontrada o no tienes permisos para eliminarla.'

    conn.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()

    return redirect('/')

@app.route('/complete/<int:task_id>', methods=['POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    conn.execute(
        'UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?',
        (task_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    return redirect('/dashboard')


@app.route('/logout')
def logout():
    # Eliminar el 'user_id' de la sesión para cerrar sesión
    session.pop('user_id', None)
    return redirect('/login')  # Redirigir al inicio de sesión

if __name__ == '__main__':
    app.run(debug=True)
