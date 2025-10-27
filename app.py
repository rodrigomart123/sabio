from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    send_from_directory, jsonify, g, abort
)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import psycopg2
import psycopg2.extras
import json, os
import uuid

# -----------------------------------------------------------------------------
# Configuração da App
# -----------------------------------------------------------------------------
app = Flask(__name__)

load_dotenv()
# ⚠️ Em produção, use uma SECRET_KEY de ambiente
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_local_key')

# E-mail (Flask-Mail) – credenciais via variáveis de ambiente
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = True if str(os.environ.get('MAIL_USE_TLS', '1')) == '1' else False
app.config['MAIL_USE_SSL'] = True if str(os.environ.get('MAIL_USE_SSL', '0')) == '1' else False
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = (
    os.environ.get('MAIL_FROM_NAME', 'SABIO – Suporte'),
    app.config['MAIL_USERNAME']
)

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Limite de upload
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------------------------------------------------------------
# Database (SQLite + PostgreSQL Render)
# -----------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)
DB_PATH = os.path.join(INSTANCE_DIR, 'local.db')

db_url = os.environ.get("DATABASE_URL", "")
USE_POSTGRES = db_url.startswith("postgres://") or db_url.startswith("postgresql://")


def get_db():
    if USE_POSTGRES:
        conn = psycopg2.connect(os.environ["DATABASE_URL"], sslmode="require")
        conn.autocommit = True
        return conn
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

def execute_query(query, params=(), fetchone=False, fetchall=False, commit=False):
    conn = get_db()
    
    try:
        if USE_POSTGRES:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # PostgreSQL usa %s como placeholder
            query = query.replace("?", "%s")
        else:
            cur = conn.cursor()

        cur.execute(query, params)

        data = None
        if fetchone:
            row = cur.fetchone()
            if row:
                data = dict(row) if not USE_POSTGRES else row
        elif fetchall:
            rows = cur.fetchall()
            if rows:
                if USE_POSTGRES:
                    data = rows
                else:
                    data = [dict(r) for r in rows]

        if commit:
            conn.commit()

        return data

    finally:
        conn.close()


def init_db():
    # Criação das tabelas (usado apenas localmente)
    conn = get_db()
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS avatars (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE NOT NULL,
        outfit TEXT,
        accessory TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS quizzes (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        is_public INTEGER DEFAULT 0,
        created_by INTEGER NOT NULL,
        cover_image_url TEXT,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE CASCADE
    )''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS questions (
        id SERIAL PRIMARY KEY,
        quiz_id INTEGER NOT NULL,
        question_text TEXT NOT NULL,
        option_a TEXT,
        option_b TEXT,
        option_c TEXT,
        option_d TEXT,
        correct_option TEXT,
        FOREIGN KEY(quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
    )''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS favorites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        quiz_id INTEGER NOT NULL,
        UNIQUE(user_id, quiz_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE
    )''')
    conn.commit()
    conn.close()

# -----------------------------------------------------------------------------
# Simple row -> object wrapper
# -----------------------------------------------------------------------------
class DBObject:
    def __init__(self, row):
        if not row:
            return
        for k in row.keys():
            setattr(self, k, row[k])

# -----------------------------------------------------------------------------
# CRUD Functions (Compatíveis com SQLite + PostgreSQL)
# -----------------------------------------------------------------------------
def get_user_by_id(user_id):
    row = execute_query("SELECT * FROM users WHERE id = ?", (user_id,), fetchone=True)
    return DBObject(row) if row else None

def get_user_by_username(username):
    row = execute_query("SELECT * FROM users WHERE username = ?", (username,), fetchone=True)
    return DBObject(row) if row else None

def get_user_by_email(email):
    row = execute_query("SELECT * FROM users WHERE email = ?", (email,), fetchone=True)
    return DBObject(row) if row else None

def create_user(username, email, password):
    password_hash = generate_password_hash(password)
    execute_query(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash),
        commit=True
    )
    row = execute_query("SELECT * FROM users WHERE username = ?", (username,), fetchone=True)
    return DBObject(row)

def update_user_password(user_id, new_password):
    password_hash = generate_password_hash(new_password)
    execute_query("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id), commit=True)

def get_avatar_by_user_id(user_id):
    row = execute_query("SELECT * FROM avatars WHERE user_id = ?", (user_id,), fetchone=True)
    return DBObject(row) if row else None

def create_avatar_for_user(user_id):
    if USE_POSTGRES:
        execute_query(
            "INSERT INTO avatars (user_id, outfit, accessory) VALUES (%s, NULL, NULL) ON CONFLICT (user_id) DO NOTHING",
            (user_id,),
            commit=True
        )
    else:
        execute_query(
            "INSERT OR IGNORE INTO avatars (user_id, outfit, accessory) VALUES (?, NULL, NULL)",
            (user_id,),
            commit=True
        )
    return get_avatar_by_user_id(user_id)

def update_avatar(user_id, outfit=None, accessory=None):
    # garante que exista
    create_avatar_for_user(user_id)
    
    # build dynamic query
    updates = []
    params = []

    if outfit is not None:
        updates.append("outfit = %s" if USE_POSTGRES else "outfit = ?")
        params.append(outfit)
    if accessory is not None:
        updates.append("accessory = %s" if USE_POSTGRES else "accessory = ?")
        params.append(accessory)

    if updates:
        query = f"UPDATE avatars SET {', '.join(updates)} WHERE user_id = %s" if USE_POSTGRES else f"UPDATE avatars SET {', '.join(updates)} WHERE user_id = ?"
        params.append(user_id)
        execute_query(query, tuple(params), commit=True)

    return get_avatar_by_user_id(user_id)


def create_quiz(title, description, is_public, created_by, cover_image_url):
    execute_query(
        "INSERT INTO quizzes (title, description, is_public, created_by, cover_image_url) VALUES (?, ?, ?, ?, ?)",
        (title, description, bool(is_public), created_by, cover_image_url),
        commit=True
    )
    row = execute_query(
        "SELECT * FROM quizzes WHERE title = ? AND created_by = ? ORDER BY id DESC LIMIT 1",
        (title, created_by),
        fetchone=True
    )
    return DBObject(row) if row else None

def get_quiz_by_id(quiz_id):
    row = execute_query("SELECT * FROM quizzes WHERE id = ?", (quiz_id,), fetchone=True)
    if not row:
        return None
    quiz = DBObject(row)
    quiz.questions = get_questions_for_quiz(quiz.id)
    return quiz

def get_quizzes_by_user(user_id):
    rows = execute_query("SELECT * FROM quizzes WHERE created_by = ?", (user_id,), fetchall=True)
    quizzes = []
    for r in rows or []:
        q = DBObject(r)
        q.questions = get_questions_for_quiz(q.id)
        quizzes.append(q)
    return quizzes

def get_public_quizzes():
    rows = execute_query("SELECT * FROM quizzes WHERE is_public = 1", fetchall=True)
    quizzes = []
    for r in rows or []:
        q = DBObject(r)
        q.questions = get_questions_for_quiz(q.id)
        quizzes.append(q)
    return quizzes

def update_quiz(quiz_id, title=None, description=None, is_public=None, cover_image_url=None):
    if title is not None:
        execute_query("UPDATE quizzes SET title = ? WHERE id = ?", (title, quiz_id), commit=True)
    if description is not None:
        execute_query("UPDATE quizzes SET description = ? WHERE id = ?", (description, quiz_id), commit=True)
    if is_public is not None:
        execute_query("UPDATE quizzes SET is_public = ? WHERE id = ?", (bool(is_public), quiz_id), commit=True)
    if cover_image_url is not None:
        execute_query("UPDATE quizzes SET cover_image_url = ? WHERE id = ?", (cover_image_url, quiz_id), commit=True)
    return get_quiz_by_id(quiz_id)

def delete_quiz_by_id(quiz_id):
    execute_query("DELETE FROM questions WHERE quiz_id = ?", (quiz_id,), commit=True)
    execute_query("DELETE FROM favorites WHERE quiz_id = ?", (quiz_id,), commit=True)
    execute_query("DELETE FROM quizzes WHERE id = ?", (quiz_id,), commit=True)

def create_question(quiz_id, question_text, option_a, option_b, option_c, option_d, correct_option):
    execute_query(
        "INSERT INTO questions (quiz_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (quiz_id, question_text, option_a, option_b, option_c, option_d, correct_option),
        commit=True
    )
    row = execute_query(
        "SELECT * FROM questions WHERE quiz_id = ? AND question_text = ?",
        (quiz_id, question_text),
        fetchone=True
    )
    return DBObject(row)

def get_question_by_id(qid):
    row = execute_query("SELECT * FROM questions WHERE id = ?", (qid,), fetchone=True)
    return DBObject(row) if row else None

def get_questions_for_quiz(quiz_id):
    rows = execute_query("SELECT * FROM questions WHERE quiz_id = ?", (quiz_id,), fetchall=True)
    return [DBObject(r) for r in rows or []]

def get_favorite(user_id, quiz_id):
    row = execute_query("SELECT * FROM favorites WHERE user_id = ? AND quiz_id = ?", (user_id, quiz_id), fetchone=True)
    return DBObject(row) if row else None

def add_favorite(user_id, quiz_id):
    if USE_POSTGRES:
        execute_query(
            "INSERT INTO favorites (user_id, quiz_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (user_id, quiz_id),
            commit=True
        )
    else:
        execute_query(
            "INSERT OR IGNORE INTO favorites (user_id, quiz_id) VALUES (?, ?)",
            (user_id, quiz_id),
            commit=True
        )

def remove_favorite(user_id, quiz_id):
    execute_query("DELETE FROM favorites WHERE user_id = ? AND quiz_id = ?", (user_id, quiz_id), commit=True)

def get_favorites_for_user(user_id):
    rows = execute_query("""
        SELECT q.* FROM quizzes q
        JOIN favorites f ON q.id = f.quiz_id
        WHERE f.user_id = ?
    """, (user_id,), fetchall=True)
    return [DBObject(r) for r in rows or []]


# -----------------------------------------------------------------------------
# Authentication helpers (session & current_user)
# -----------------------------------------------------------------------------
def current_user():
    uid = session.get('user_id')
    if uid is None:
        return None
    user = get_user_by_id(uid)
    if not user:
        return None
    # Attach avatar object for compatibility with previous code expectations
    avatar = get_avatar_by_user_id(user.id)
    user.avatar = avatar
    return user

@app.before_request
def load_user_into_global():
    g.user = current_user()

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'img'),
        'logoapp.jpg',
        mimetype='image/jpeg'
    )

@app.route('/health')
def health():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.fetchone()
        conn.close()
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html', username=g.user.username if g.user else None)

# -----------------------------------------------------------------------------
# Login / Register / Logout
# -----------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')

        # Try by username then email
        user = get_user_by_username(identifier) or get_user_by_email(identifier)
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard_profile'))
        else:
            message = 'Login inválido. Tenta outra vez.'
    return render_template('login.html', message=message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not username or not email or not password:
            message = 'Preenche todos os campos.'
        elif get_user_by_username(username):
            message = 'Utilizador já existe.'
        elif get_user_by_email(email):
            message = 'E-mail já registado.'
        else:
            user = create_user(username, email, password)
            return redirect(url_for('login'))

    return render_template('register.html', message=message)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

# -----------------------------------------------------------------------------
# Password reset via email (itsdangerous + Flask-Mail)
# -----------------------------------------------------------------------------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    message = None
    if request.method == 'POST':
        email_destino = request.form.get('email', '').strip().lower()
        user = get_user_by_email(email_destino)

        # Send only if credentials configured and email exists
        if user and app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
            token = s.dumps(email_destino, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Recuperação de senha', recipients=[email_destino])
            msg.body = (
                f"Clique no link para redefinir a sua palavra-passe: {reset_url}\n"
                f"Mensagem automática | SABIO."
            )
            try:
                mail.send(msg)
            except Exception as e:
                print('Erro ao enviar e-mail:', e)
        message = 'Se este email existir, enviámos um link para redefinir a palavra-passe.'
    return render_template('forgot.html', message=message)

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hour
    except SignatureExpired:
        return 'Link expirado.'
    except BadSignature:
        return 'Link inválido.'

    if request.method == 'POST':
        nova_senha = request.form.get('password', '')
        if not nova_senha:
            return render_template('reset.html', message='Indica uma nova palavra-passe.')

        user = get_user_by_email(email)
        if not user:
            return 'Utilizador não encontrado.'

        update_user_password(user.id, nova_senha)
        return redirect(url_for('login'))

    return render_template('reset.html')

# -----------------------------------------------------------------------------
# Dashboard & profile (avatar)
# -----------------------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    if not g.user:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard_profile'))

@app.route('/dashboard/profile')
def dashboard_profile():
    if not g.user:
        return redirect(url_for('login'))

    avatar = g.user.avatar
    if not avatar:
        avatar = create_avatar_for_user(g.user.id)

    user_context = {
        'username': g.user.username,
        'email': g.user.email,
        'avatar': {
            'accessory': avatar.accessory if avatar else None,
            'outfit': avatar.outfit if avatar else None,
        },
    }

    return render_template('profile.html', user=user_context, active_page='perfil')

# -----------------------------------------------------------------------------
# Quiz / Question / Favorite routes
# -----------------------------------------------------------------------------
@app.route('/dashboard/my_sets')
def my_sets():
    if not g.user:
        return redirect(url_for('login'))

    quizzes = get_quizzes_by_user(g.user.id)
    return render_template('my_sets.html', quizzes=quizzes, active_page='my_sets')

@app.route('/dashboard/create_quiz', methods=['GET', 'POST'])
def create_quiz_route():
    if not g.user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        is_public = bool(request.form.get('is_public'))
        cover_image = request.files.get('cover_image')
        cover_image_url = None

        if cover_image and allowed_file(cover_image.filename):
            filename = f"{uuid.uuid4().hex}_{secure_filename(cover_image.filename)}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            cover_image.save(filepath)
            cover_image_url = f'/static/uploads/{filename}'

        quiz = create_quiz(title, description, is_public, g.user.id, cover_image_url)
        return redirect(url_for('add_questions', quiz_id=quiz.id))

    return render_template('create_quiz_form.html', active_page='my_sets')

@app.route('/dashboard/add_questions/<int:quiz_id>', methods=['GET', 'POST'])
def add_questions(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return "Quiz não encontrado.", 404
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    if request.method == 'POST':
        question_text = request.form.get('question_text')
        option_a = request.form.get('option_a')
        option_b = request.form.get('option_b')
        option_c = request.form.get('option_c')
        option_d = request.form.get('option_d')
        correct_option = request.form.get('correct_option')
        create_question(quiz.id, question_text, option_a, option_b, option_c, option_d, correct_option)

    # Reload questions for display
    quiz.questions = get_questions_for_quiz(quiz.id)
    return render_template('add_questions.html', quiz=quiz, active_page='my_sets')

@app.route('/dashboard/discover')
def play_quiz_list():
    if not g.user:
        return redirect(url_for('login'))

    quizzes = get_public_quizzes()
    return render_template('discover.html', quizzes=quizzes, active_page='discover')

@app.route('/play/<int:quiz_id>')
def play_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return "Quiz não encontrado.", 404

    # questions already attached in get_quiz_by_id
    questions = []
    for q in quiz.questions:
        questions.append({
            'id': q.id,
            'question_text': q.question_text,
            'option_a': q.option_a,
            'option_b': q.option_b,
            'option_c': q.option_c,
            'option_d': q.option_d,
            'correct_option': q.correct_option
        })
    return render_template('play_quiz_form.html', quiz=quiz, questions=questions)

@app.route('/dashboard/quiz/<int:quiz_id>')
def quiz_detail(quiz_id):
    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return "Quiz não encontrado.", 404

    is_favorited = False
    if g.user:
        fav = get_favorite(g.user.id, quiz.id)
        is_favorited = fav is not None

    creator = get_user_by_id(quiz.created_by)
    return render_template(
        "quiz_detail.html",
        quiz=quiz,
        creator=creator,
        is_favorited=is_favorited
    )

@app.route('/dashboard/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return "Quiz não encontrado.", 404
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        is_public = bool(request.form.get('is_public'))

        cover_image = request.files.get('cover_image')
        cover_image_url = None
        if cover_image and allowed_file(cover_image.filename):
            filename = f"{uuid.uuid4().hex}_{secure_filename(cover_image.filename)}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            cover_image.save(filepath)
            cover_image_url = f'/static/uploads/{filename}'

        update_quiz(quiz.id, title=title, description=description, is_public=is_public, cover_image_url=cover_image_url)
        return redirect(url_for('my_sets'))

    return render_template('edit_quiz_form.html', quiz=quiz, active_page='my_sets')

@app.route('/dashboard/delete_quiz/<int:quiz_id>', methods=['POST'])
def delete_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return "Quiz não encontrado.", 404
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    delete_quiz_by_id(quiz.id)
    return redirect(url_for('my_sets'))

@app.route('/favorite/<int:quiz_id>', methods=['POST'])
def toggle_favorite(quiz_id):
    if not g.user:
        return jsonify({'success': False, 'error': 'Não autenticado'}), 401

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return jsonify({'success': False, 'error': 'Quiz não encontrado'}), 404

    fav = get_favorite(g.user.id, quiz.id)
    if fav:
        remove_favorite(g.user.id, quiz.id)
        return jsonify({'favorited': False})
    else:
        add_favorite(g.user.id, quiz.id)
        return jsonify({'favorited': True})

@app.route('/dashboard/favorites')
def favorites():
    if not g.user:
        return redirect(url_for('login'))

    favorites = get_favorites_for_user(g.user.id)
    return render_template('favorites.html', quizzes=favorites, active_page='favorites')

@app.route('/dashboard/submit_quiz/<int:quiz_id>', methods=['POST'])
def submit_quiz(quiz_id):
    if not g.user:
        return jsonify({'error': 'Não autenticado'}), 401

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return jsonify({'error': 'Quiz não encontrado'}), 404

    respostas = request.get_json() or {}
    score = 0
    for q in quiz.questions:
        resposta_user = respostas.get(f"q{q.id}")
        if resposta_user and resposta_user == q.correct_option:
            score += 1

    return jsonify({'score': score, 'total': len(quiz.questions)})

@app.route('/dashboard/finish_quiz/<int:quiz_id>', methods=['POST'])
def finish_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = get_quiz_by_id(quiz_id)
    if not quiz:
        return "Quiz não encontrado.", 404
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    return redirect(url_for('my_sets'))

@app.route('/save_avatar', methods=['POST'])
def save_avatar():
    if not g.user:
        return jsonify({'success': False, 'error': 'Não autenticado'}), 401

    data = request.get_json(silent=True) or {}
    accessory = data.get('accessory')
    outfit = data.get('outfit')

    avatar = get_avatar_by_user_id(g.user.id)
    if not avatar:
        create_avatar_for_user(g.user.id)
        avatar = get_avatar_by_user_id(g.user.id)

    if accessory is not None:
        accessory_clean = str(accessory).replace('.png', '')
    else:
        accessory_clean = None

    if outfit is not None:
        outfit_clean = str(outfit).replace('.png', '')
    else:
        outfit_clean = None

    update_avatar(g.user.id, outfit=outfit_clean, accessory=accessory_clean)
    avatar = get_avatar_by_user_id(g.user.id)
    return jsonify({'success': True, 'avatar': {
        'accessory': avatar.accessory,
        'outfit': avatar.outfit
    }})

# -----------------------------------------------------------------------------
# Start
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    # Dica: em dev podes imprimir as variáveis de e-mail para confirmar
    print('EMAIL_USER =', os.environ.get('EMAIL_USER'))
    print('EMAIL_PASS set =', bool(os.environ.get('EMAIL_PASS')))

    # Run server
    app.run(debug=True)
