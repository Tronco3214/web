from extensions import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    surveys = db.relationship('Survey', back_populates='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    def is_active(self):
        return True

    def __repr__(self):
        return f'<User {self.username}>'


class Survey(db.Model):
    __tablename__ = 'surveys'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    public_access_key = db.Column(db.String(50), unique=True, nullable=True)
    is_public = db.Column(db.Boolean, default=False)
    # Relaciones
    user = db.relationship('User', back_populates='surveys')
    questions = db.relationship('Question', back_populates='survey', lazy=True, cascade='all, delete-orphan')
    responses = db.relationship('Response', back_populates='survey', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Survey {self.title}>'


class Question(db.Model):
    __tablename__ = 'questions'
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'text', 'single', 'multiple', 'scale'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    survey_id = db.Column(db.Integer, db.ForeignKey('surveys.id'), nullable=False)
    
    # Relaciones
    survey = db.relationship('Survey', back_populates='questions')
    options = db.relationship('QuestionOption', back_populates='question', lazy=True, cascade='all, delete-orphan')
    answers = db.relationship('Answer', back_populates='question', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Question {self.id}: {self.text[:30]}...>'


class QuestionOption(db.Model):
    __tablename__ = 'question_options'
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    
    # Relaciones
    question = db.relationship('Question', back_populates='options')
    answers = db.relationship('Answer', back_populates='selected_option')

    def __repr__(self):
        return f'<QuestionOption {self.id}: {self.text[:30]}...>'


class Response(db.Model):
    __tablename__ = 'responses'
    
    id = db.Column(db.Integer, primary_key=True)
    respondent_email = db.Column(db.String(150))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    ip_address = db.Column(db.String(45))
    survey_id = db.Column(db.Integer, db.ForeignKey('surveys.id'), nullable=False)
    
    # Relaciones
    survey = db.relationship('Survey', back_populates='responses')
    answers = db.relationship('Answer', back_populates='response', cascade='all, delete-orphan')

    @property
    def is_complete(self):
        return self.completed_at is not None

    def __repr__(self):
        return f'<Response {self.id} from {self.respondent_email}>'


class Answer(db.Model):
    __tablename__ = 'answers'
    
    id = db.Column(db.Integer, primary_key=True)
    text_answer = db.Column(db.Text)
    numeric_answer = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Claves foráneas
    response_id = db.Column(db.Integer, db.ForeignKey('responses.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    selected_option_id = db.Column(db.Integer, db.ForeignKey('question_options.id'))
    
    # Relaciones
    response = db.relationship('Response', back_populates='answers')
    question = db.relationship('Question', back_populates='answers')
    selected_option = db.relationship('QuestionOption', back_populates='answers')

    def __repr__(self):
        return f'<Answer {self.id} for question {self.question_id}>'
