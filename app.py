from flask import Flask, request, jsonify, render_template
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
import re

from config import Config
from models import db, User

# Initialisation de l'application
app = Flask(__name__)
app.config.from_object(Config)

# Initialisation des extensions
db.init_app(app)
bcrypt = Bcrypt(app)

# ==================== UTILITAIRES ====================

def validate_email(email):
    """Valider le format de l'email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Valider la force du mot de passe"""
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    if not re.search(r'[A-Z]', password):
        return False, "Le mot de passe doit contenir au moins une majuscule"
    if not re.search(r'[a-z]', password):
        return False, "Le mot de passe doit contenir au moins une minuscule"
    if not re.search(r'\d', password):
        return False, "Le mot de passe doit contenir au moins un chiffre"
    return True, "Mot de passe valide"

def generate_token(user_id, token_type='access'):
    """Générer un token JWT"""
    expiration = datetime.utcnow() + (
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] if token_type == 'access' 
        else app.config['JWT_REFRESH_TOKEN_EXPIRES']
    )
    
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'iat': datetime.utcnow(),
        'type': token_type
    }
    
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    """Décoder et valider un token JWT"""
    try:
        return jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def token_required(f):
    """Décorateur pour protéger les routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Format du token invalide'}), 401
        
        if not token:
            return jsonify({'error': 'Token manquant'}), 401
        
        payload = decode_token(token)
        if not payload or payload.get('type') != 'access':
            return jsonify({'error': 'Token invalide ou expiré'}), 401
        
        current_user = User.query.get(payload['user_id'])
        if not current_user or not current_user.is_active:
            return jsonify({'error': 'Utilisateur non trouvé ou inactif'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# ==================== ROUTES HTML ====================

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register-page')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# ==================== ROUTES API ====================

@app.route('/api/register', methods=['POST'])
def register():
    """Endpoint d'inscription"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Aucune donnée fournie'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        password_confirm = data.get('password_confirm', '')
        
        # Validations
        if not email or not password:
            return jsonify({'error': 'Email et mot de passe requis'}), 400
        
        if not validate_email(email):
            return jsonify({'error': 'Format d\'email invalide'}), 400
        
        if password != password_confirm:
            return jsonify({'error': 'Les mots de passe ne correspondent pas'}), 400
        
        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Vérifier si l'utilisateur existe
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Cet email est déjà utilisé'}), 409
        
        # Créer l'utilisateur
        pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, pwd_hash=pwd_hash)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Générer les tokens
        access_token = generate_token(new_user.id, 'access')
        refresh_token = generate_token(new_user.id, 'refresh')
        
        return jsonify({
            'message': 'Inscription réussie',
            'user': new_user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Endpoint de connexion"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Aucune donnée fournie'}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email et mot de passe requis'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not bcrypt.check_password_hash(user.pwd_hash, password):
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Compte désactivé'}), 403
        
        access_token = generate_token(user.id, 'access')
        refresh_token = generate_token(user.id, 'refresh')
        
        return jsonify({
            'message': 'Connexion réussie',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/api/refresh', methods=['POST'])
def refresh():
    """Renouveler le access token"""
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token manquant'}), 400
        
        payload = decode_token(refresh_token)
        
        if not payload or payload.get('type') != 'refresh':
            return jsonify({'error': 'Refresh token invalide ou expiré'}), 401
        
        new_access_token = generate_token(payload['user_id'], 'access')
        
        return jsonify({'access_token': new_access_token}), 200
        
    except Exception as e:
        return jsonify({'error': f'Erreur serveur: {str(e)}'}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def profile(current_user):
    """Route protégée - Profil utilisateur"""
    return jsonify({'user': current_user.to_dict()}), 200

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Déconnexion"""
    return jsonify({'message': 'Déconnexion réussie'}), 200

# ==================== INITIALISATION ====================

def init_db():
    """Initialiser la base de données"""
    with app.app_context():
        db.create_all()
        print("✅ Base de données initialisée avec succès")

if __name__ == '__main__':
    init_db()
    print(f"🚀 Application démarrée en mode: {app.config['DEBUG'] and 'DEVELOPMENT' or 'PRODUCTION'}")
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=5000)