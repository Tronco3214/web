import os
import logging
import json
import uuid
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from extensions import db
from models import User, Survey, Answer, Question, Response, QuestionOption

def generate_access_key():
    """Genera una clave de acceso única para la encuesta"""
    return str(uuid.uuid4())[:8]

# Configuración de la aplicación
def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'development_secret_key'),
        SQLALCHEMY_DATABASE_URI='mysql+pymysql://root:123456@localhost/encuesta_db',
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ECHO=True
    )
    return app

# Inicialización
app = create_app()
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Configuración de logging
def setup_logging(app):
    handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

# User loader para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rutas de autenticación
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logout_user()
        app.logger.info("Usuario ya autenticado, forzando logout")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            user = User.query.filter_by(username=username).first()
            if not user or not user.check_password(password):
                flash('Usuario o contraseña incorrectos', 'danger')
                return render_template('login.html')

            login_user(user)
            flash(f'¡Bienvenido, {username}!', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            app.logger.error(f"Error durante el login: {str(e)}")
            flash('Ocurrió un error durante el inicio de sesión', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash('Por favor, completa todos los campos', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('El correo electrónico ya está registrado', 'danger')
            return redirect(url_for('register'))

        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registro exitoso. Inicia sesión', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error en el registro: {str(e)}', 'danger')

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada exitosamente', 'success')
    return redirect(url_for('login'))

# Rutas de la aplicación principal
@app.route('/index')
@login_required
def index():
    try:
        surveys = Survey.query.filter_by(user_id=current_user.id).all()
        return render_template('index.html', surveys=surveys)
    except Exception as e:
        app.logger.error(f"Error al cargar la página principal: {str(e)}")
        flash('Ocurrió un error al cargar las encuestas.', 'danger')
        return render_template('index.html', surveys=[])

# Rutas de encuestas
@app.route('/surveys')
def list_surveys():
    surveys = Survey.query.all()
    return render_template('list_surveys.html', surveys=surveys)

@app.route('/survey/<int:survey_id>')
@login_required
def view_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    if survey.user_id != current_user.id:
        flash('No tienes permiso para ver esta encuesta.', 'danger')
        return redirect(url_for('index'))
    return render_template('view_survey.html', survey=survey)

@app.route('/survey/create', methods=['GET', 'POST'])
@login_required
def create_survey():
    if request.method == 'POST':
        try:
            # Generar una clave de acceso única
            import secrets
            public_access_key = secrets.token_urlsafe(16)
            
            # Crear la encuesta
            survey = Survey(
                title=request.form.get('title'),
                description=request.form.get('description'),
                user_id=current_user.id,
                public_access_key=public_access_key,
                is_public=True  # Por defecto la encuesta es pública
            )
            db.session.add(survey)
            db.session.flush()

            # Procesar las preguntas y sus opciones
            questions_data = request.form.getlist('questions')
            for q_data in questions_data:
                if isinstance(q_data, str):
                    q_data = json.loads(q_data)
                process_question_options(q_data, survey.id)

            db.session.commit()
            flash('Encuesta creada exitosamente', 'success')
            
            # Generar y mostrar el enlace de la encuesta
            survey_link = url_for('join_survey', access_key=survey.public_access_key, _external=True)
            flash(f'Enlace para compartir la encuesta: {survey_link}', 'info')
            
            return redirect(url_for('view_survey', survey_id=survey.id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al crear la encuesta: {str(e)}")
            flash('Error al crear la encuesta. Por favor, intenta nuevamente.', 'danger')

    return render_template('create_survey.html')

@app.route('/survey/<int:survey_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    
    if survey.user_id != current_user.id:
        flash('No tienes permiso para editar esta encuesta.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')

        if not title:
            flash('El título es requerido.', 'danger')
            return render_template('edit_survey.html', survey=survey)

        try:
            survey.title = title
            survey.description = description
            db.session.commit()
            flash('Encuesta actualizada exitosamente.', 'success')
            return redirect(url_for('view_survey', survey_id=survey.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar la encuesta: {str(e)}', 'danger')

    return render_template('edit_survey.html', survey=survey)

@app.route('/survey/<int:survey_id>/delete', methods=['POST'])
@login_required
def delete_survey(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    
    if survey.user_id != current_user.id:
        flash('No tienes permiso para eliminar esta encuesta.', 'danger')
        return redirect(url_for('index'))

    try:
        db.session.delete(survey)
        db.session.commit()
        flash('Encuesta eliminada exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar la encuesta: {str(e)}', 'danger')

    return redirect(url_for('index'))

# Rutas de preguntas
@app.route('/add-question/<int:survey_id>', methods=['GET', 'POST'])
@login_required
def add_question(survey_id):
    survey = Survey.query.filter_by(id=survey_id, user_id=current_user.id).first()
    
    if not survey:
        flash('Encuesta no encontrada o no tienes permisos para editarla.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        question_text = request.form['question_text']
        
        if not question_text.strip():
            flash('El texto de la pregunta no puede estar vacío.', 'warning')
            return redirect(url_for('add_question', survey_id=survey_id))

        try:
            new_question = Question(text=question_text, survey_id=survey.id)
            db.session.add(new_question)
            db.session.commit()
            flash('Pregunta agregada exitosamente.', 'success')
            return redirect(url_for('add_question', survey_id=survey_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al agregar la pregunta: {str(e)}', 'danger')

    return render_template('add_question.html', survey=survey)

# Inicialización de la aplicación
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    setup_logging(app)
    
    try:
        with app.app_context():
            db.session.execute('SELECT 1')
            print("Conexión a la base de datos exitosa")
    except Exception as e:
        print(f"Error de conexión a la base de datos: {e}")
    
    app.run(debug=True, port=5000)

@app.route('/survey/<int:survey_id>/generate_access_key', methods=['POST'])
@login_required
def generate_access_key(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    
    if survey.user_id != current_user.id:
        flash('No tienes permiso para generar una clave de acceso', 'danger')
        return redirect(url_for('index'))

    # Generar una clave única
    import secrets
    survey.public_access_key = secrets.token_urlsafe(16)
    survey.is_public = True
    
    try:
        db.session.commit()
        flash('Clave de acceso generada exitosamente', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al generar la clave: {str(e)}', 'danger')
    
    return redirect(url_for('view_survey', survey_id=survey.id))

@app.route('/survey/<int:survey_id>/completed')
def survey_completed(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    return render_template('survey_completed.html', survey=survey)

@app.route('/join/<access_key>', methods=['GET', 'POST'])
def join_survey(access_key):
    # Buscar la encuesta por la clave de acceso
    survey = Survey.query.filter_by(
        public_access_key=access_key,
        is_public=True,
        is_active=True
    ).first_or_404()

    # Verificar si la encuesta está activa y dentro de las fechas válidas
    current_date = datetime.utcnow()
    if survey.end_date and current_date > survey.end_date:
        flash('Esta encuesta ya ha finalizado.', 'warning')
        return redirect(url_for('index'))

    if survey.start_date and current_date < survey.start_date:
        flash('Esta encuesta aún no está disponible.', 'warning')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            # Validar el email del respondente si es requerido
            respondent_email = request.form.get('email')
            if survey.require_email and not respondent_email:
                flash('El correo electrónico es requerido para esta encuesta.', 'danger')
                return render_template('join_survey.html', survey=survey)

            # Verificar si el usuario ya respondió la encuesta (si se requiere email)
            if respondent_email and survey.one_response_per_email:
                existing_response = Response.query.filter_by(
                    survey_id=survey.id,
                    respondent_email=respondent_email
                ).first()
                if existing_response:
                    flash('Ya has respondido esta encuesta anteriormente.', 'warning')
                    return redirect(url_for('index'))

            # Crear una nueva respuesta
            response = Response(
                survey_id=survey.id,
                respondent_email=respondent_email,
                ip_address=request.remote_addr,
                started_at=datetime.utcnow()
            )
            db.session.add(response)
            db.session.flush()  # Para obtener el ID de la respuesta

            # Procesar las respuestas para cada pregunta
            for question in survey.questions:
                answer_text = request.form.get(f'question_{question.id}')
                
                # Validar respuestas requeridas
                if question.is_required and not answer_text:
                    flash(f'La pregunta "{question.text}" es obligatoria.', 'danger')
                    return render_template('join_survey.html', survey=survey)

                if answer_text:
                    # Validar respuestas según el tipo de pregunta
                    if question.type == 'scale':
                        try:
                            value = int(answer_text)
                            if not (1 <= value <= 10):
                                raise ValueError
                        except ValueError:
                            flash('Por favor, proporciona un valor válido para la escala (1-10).', 'danger')
                            return render_template('join_survey.html', survey=survey)

                    # Crear la respuesta
                    answer = Answer(
                        response_id=response.id,
                        question_id=question.id,
                        text_answer=answer_text
                    )
                    db.session.add(answer)

            # Registrar la finalización de la respuesta
            response.completed_at = datetime.utcnow()
            
            # Incrementar el contador de respuestas de la encuesta
            survey.response_count = Survey.response_count + 1
            
            db.session.commit()

            flash('¡Gracias por completar la encuesta!', 'success')
            return redirect(url_for('survey_completed', survey_id=survey.id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al procesar la encuesta: {str(e)}")
            flash('Error al procesar tus respuestas. Por favor, intenta nuevamente.', 'danger')
            return render_template('join_survey.html', survey=survey)

    # Para solicitudes GET, mostrar el formulario de la encuesta
    return render_template('join_survey.html', survey=survey)

@app.route('/survey/<int:survey_id>/completed')
def survey_completed(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    return render_template('survey_completed.html', survey=survey)

@app.route('/survey/<int:survey_id>/completed')
def survey_completed(survey_id):
    survey = Survey.query.get_or_404(survey_id)
    return render_template('survey_completed.html', survey=survey)

# Función auxiliar para procesar la creación de preguntas con opciones
def process_question_options(question_data, survey_id):
    question = Question(
        text=question_data.get('text'),
        type=question_data.get('type'),
        survey_id=survey_id
    )
    db.session.add(question)
    db.session.flush()  # Para obtener el ID de la pregunta

    # Si la pregunta es de tipo 'single' o 'multiple', procesar las opciones
    if question.type in ['single', 'multiple']:
        options = question_data.get('options', [])
        for option_text in options:
            option = QuestionOption(
                text=option_text,
                question_id=question.id
            )
            db.session.add(option)

    return question

@app.route('/survey/create', methods=['GET', 'POST'])
@login_required
def create_survey():
    if request.method == 'POST':
        try:
            # Crear la encuesta
            survey = Survey(
                title=request.form.get('title'),
                description=request.form.get('description'),
                user_id=current_user.id
            )
            db.session.add(survey)
            db.session.flush()  # Para obtener el ID de la encuesta

            # Procesar las preguntas y sus opciones
            questions_data = request.form.getlist('questions')
            for q_data in questions_data:
                if isinstance(q_data, str):
                    q_data = json.loads(q_data)
                process_question_options(q_data, survey.id)

            db.session.commit()
            flash('Encuesta creada exitosamente', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error al crear la encuesta: {str(e)}")
            flash('Error al crear la encuesta. Por favor, intenta nuevamente.', 'danger')

    return render_template('create_survey.html')