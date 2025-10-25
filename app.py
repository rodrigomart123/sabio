from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, jsonify, g
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json, os
import uuid



# -----------------------------------------------------------------------------
# Configuração da App
# -----------------------------------------------------------------------------
app = Flask(__name__)

# ⚠️ Em produção, use uma SECRET_KEY de ambiente (ex: export SECRET_KEY="...")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Base de dados (SQLite para desenvolvimento; fácil migrar depois)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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
# Modelos
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)

    avatar = db.relationship('Avatar', back_populates='user', uselist=False, cascade='all, delete-orphan')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Avatar(db.Model):
    __tablename__ = "avatars"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)

    outfit = db.Column(db.String(50))
    accessory = db.Column(db.String(50))

    user = db.relationship("User", back_populates="avatar")






# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def current_user():
    uid = session.get('user_id')
    if uid is None:
        return None
    return User.query.get(uid)


@app.before_request
def load_user_into_global():
    g.user = current_user()


# -----------------------------------------------------------------------------
# Rotas estáticas / utilitárias
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
    # rota simples para confirmar que a app e a BD estão ok
    try:
        db.session.execute(db.select(User).limit(1)).first()
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': str(e)}, 500


# -----------------------------------------------------------------------------
# Páginas principais
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    # Renderiza a tua página inicial;
    # passa g.user para o template (podes usar {{ g.user.username }} se autenticado)
    return render_template('index.html', username=g.user.username if g.user else None)


# -----------------------------------------------------------------------------
# Autenticação: Login / Registo / Logout
# -----------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()  # username OU email
        password = request.form.get('password', '')

        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and user.check_password(password):
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
        elif User.query.filter_by(username=username).first():
            message = 'Utilizador já existe.'
        elif User.query.filter_by(email=email).first():
            message = 'E-mail já registado.'
        else:
            u = User(username=username, email=email)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('register.html', message=message)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))


# -----------------------------------------------------------------------------
# Recuperação de senha via e-mail
# -----------------------------------------------------------------------------
@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    message = None
    if request.method == 'POST':
        email_destino = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email_destino).first()

        # Enviar sempre a mesma mensagem para não revelar se o e-mail existe
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
                # Evitar crash se o mail falhar; podes logar e tratar como precisares
                print('Erro ao enviar e-mail:', e)
        message = 'Se este email existir, enviámos um link para redefinir a palavra-passe.'

    return render_template('forgot.html', message=message)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1h
    except SignatureExpired:
        return 'Link expirado.'
    except BadSignature:
        return 'Link inválido.'

    if request.method == 'POST':
        nova_senha = request.form.get('password', '')
        if not nova_senha:
            return render_template('reset.html', message='Indica uma nova palavra-passe.')

        user = User.query.filter_by(email=email).first()
        if not user:
            return 'Utilizador não encontrado.'

        user.set_password(nova_senha)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('reset.html')


# -----------------------------------------------------------------------------
# Dashboard & Perfil (Avatar)
# -----------------------------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    if not g.user:
        return redirect(url_for('login'))
    # Se tiveres uma página geral de dashboard, renderiza aqui
    return redirect(url_for('dashboard_profile'))


@app.route('/dashboard/profile')
def dashboard_profile():
    if not g.user:
        return redirect(url_for('login'))

    avatar = g.user.avatar
    if not avatar:
        avatar = Avatar(user_id=g.user.id)
        db.session.add(avatar)
        db.session.commit()

    user_context = {
        'username': g.user.username,
        'email': g.user.email,
        'avatar': {
            'accessory': avatar.accessory,
            'outfit': avatar.outfit,
        },
    }

    return render_template('profile.html', user=user_context, active_page='perfil')

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    is_public = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cover_image_url = db.Column(db.String(255), nullable=True)

    # Relação com perguntas
    questions = db.relationship('Question', back_populates='quiz', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Quiz {self.title}>'
    
class Favorite(db.Model):
    __tablename__ = 'favorites'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)

    __table_args__ = (db.UniqueConstraint('user_id', 'quiz_id', name='uq_user_quiz'),)


class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_text = db.Column(db.String(255), nullable=False)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)  # 'A', 'B', 'C', 'D'

    quiz = db.relationship('Quiz', back_populates='questions')

    def __repr__(self):
        return f'<Question {self.question_text[:30]}...>'


@app.route('/dashboard/my_sets')
def my_sets():
    if not g.user:
        return redirect(url_for('login'))

    quizzes = Quiz.query.filter_by(created_by=g.user.id).all()
    # Renderiza a página dos "meus sets"
    return render_template('my_sets.html', quizzes=quizzes, active_page='my_sets')


@app.route('/dashboard/create_quiz', methods=['GET', 'POST'])
def create_quiz():
    if not g.user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        is_public = bool(request.form.get('is_public'))

        cover_image = request.files.get('cover_image')
        cover_image_url = None

        cover_image = request.files.get('cover_image')
        if cover_image and allowed_file(cover_image.filename):
            # Cria um nome único usando UUID
            filename = f"{uuid.uuid4().hex}_{secure_filename(cover_image.filename)}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            cover_image.save(filepath)
            cover_image_url = f'/static/uploads/{filename}'

        quiz = Quiz(
            title=title,
            description=description,
            is_public=is_public,
            created_by=g.user.id,
            cover_image_url=cover_image_url
        )
        db.session.add(quiz)
        db.session.commit()
        return redirect(url_for('add_questions', quiz_id=quiz.id))

    return render_template('create_quiz_form.html', active_page='my_sets')




@app.route('/dashboard/add_questions/<int:quiz_id>', methods=['GET', 'POST'])
def add_questions(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    if request.method == 'POST':
        q = Question(
            quiz_id=quiz.id,
            question_text=request.form.get('question_text'),
            option_a=request.form.get('option_a'),
            option_b=request.form.get('option_b'),
            option_c=request.form.get('option_c'),
            option_d=request.form.get('option_d'),
            correct_option=request.form.get('correct_option')
        )
        db.session.add(q)
        db.session.commit()

    return render_template('add_questions.html', quiz=quiz, active_page='my_sets')

@app.route('/dashboard/discover')
def play_quiz_list():
    if not g.user:
        return redirect(url_for('login'))

    # Pega todos os quizzes públicos
    quizzes = Quiz.query.filter_by(is_public=True).all()

    return render_template('discover.html', quizzes=quizzes, active_page='discover')


@app.route('/play/<int:quiz_id>')
def play_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = [
        {
            'id': q.id,
            'question_text': q.question_text,
            'option_a': q.option_a,
            'option_b': q.option_b,
            'option_c': q.option_c,
            'option_d': q.option_d,
            'correct_option': q.correct_option
        }
        for q in quiz.questions
    ]

    return render_template('play_quiz_form.html', quiz=quiz, questions=questions)


@app.route("/dashboard/quiz/<int:quiz_id>")
def quiz_detail(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    is_favorited = False
    if g.user:
        is_favorited = Favorite.query.filter_by(
            user_id=g.user.id, quiz_id=quiz.id
        ).first() is not None

    # Podes buscar o criador se quiseres mostrar o nome:
    creator = User.query.get(quiz.created_by)

    return render_template(
        "quiz_detail.html",
        quiz=quiz,
        creator=creator,
        is_favorited=is_favorited
    )


# ------------------------------
# Editar e apagar quizzes
# ------------------------------

@app.route('/dashboard/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
def edit_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    if request.method == 'POST':
        quiz.title = request.form.get('title')
        quiz.description = request.form.get('description')
        quiz.is_public = bool(request.form.get('is_public'))

        cover_image = request.files.get('cover_image')
        if cover_image and allowed_file(cover_image.filename):
            filename = f"{uuid.uuid4().hex}_{secure_filename(cover_image.filename)}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            cover_image.save(filepath)
            quiz.cover_image_url = f'/static/uploads/{filename}'

        db.session.commit()
        return redirect(url_for('my_sets'))

    return render_template('edit_quiz_form.html', quiz=quiz, active_page='my_sets')


@app.route('/dashboard/delete_quiz/<int:quiz_id>', methods=['POST'])
def delete_quiz(quiz_id):
    if not g.user:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    db.session.delete(quiz)
    db.session.commit()
    return redirect(url_for('my_sets'))


# ------------------------------
# Favoritar / desfavoritar quizzes
# ------------------------------

@app.route('/favorite/<int:quiz_id>', methods=['POST'])
def toggle_favorite(quiz_id):
    if not g.user:
        return jsonify({'success': False, 'error': 'Não autenticado'}), 401

    quiz = Quiz.query.get_or_404(quiz_id)
    fav = Favorite.query.filter_by(user_id=g.user.id, quiz_id=quiz.id).first()

    if fav:
        db.session.delete(fav)
        db.session.commit()
        return jsonify({'favorited': False})
    else:
        new_fav = Favorite(user_id=g.user.id, quiz_id=quiz.id)
        db.session.add(new_fav)
        db.session.commit()
        return jsonify({'favorited': True})


@app.route('/dashboard/favorites')
def favorites():
    if not g.user:
        return redirect(url_for('login'))

    favorites = (
        db.session.query(Quiz)
        .join(Favorite, Quiz.id == Favorite.quiz_id)
        .filter(Favorite.user_id == g.user.id)
        .all()
    )

    return render_template('favorites.html', quizzes=favorites, active_page='favorites')




@app.route('/dashboard/submit_quiz/<int:quiz_id>', methods=['POST'])
def submit_quiz(quiz_id):
    if not g.user:
        return jsonify({'error': 'Não autenticado'}), 401

    quiz = Quiz.query.get_or_404(quiz_id)
    respostas = request.get_json()
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

    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != g.user.id:
        return "Sem permissão.", 403

    # Aqui podes fazer coisas como:
    # - marcar o quiz como ativo/publicado
    # - enviar uma notificação
    # Neste exemplo apenas redireciona para o dashboard
    return redirect(url_for('my_sets'))

@app.route('/save_avatar', methods=['POST'])
def save_avatar():
    if not g.user:
        return jsonify({'success': False, 'error': 'Não autenticado'}), 401

    data = request.get_json(silent=True) or {}
    accessory = data.get('accessory')
    outfit = data.get('outfit')

    avatar = g.user.avatar
    if not avatar:
        avatar = Avatar(user_id=g.user.id)
        db.session.add(avatar)

    if accessory is not None:
        avatar.accessory = str(accessory).replace('.png', '')
    if outfit is not None:
        avatar.outfit = str(outfit).replace('.png', '')

    db.session.commit()
    return jsonify({'success': True, 'avatar': {
        'accessory': avatar.accessory,
        'outfit': avatar.outfit
    }})




# -----------------------------------------------------------------------------
# Start
# -----------------------------------------------------------------------------

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Dica: em dev podes imprimir as variáveis de e-mail para confirmar
    print('EMAIL_USER =', os.environ.get('EMAIL_USER'))
    print('EMAIL_PASS set =', bool(os.environ.get('EMAIL_PASS')))
    
    app.run(debug=True)
