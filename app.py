print("Starting Flask app...")
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
CORS(app)

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ================= MODELS =================

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    duration = db.Column(db.String(50))
    start_date = db.Column(db.String(50))
    description = db.Column(db.String(300))
    skills = db.Column(db.String(200))
    category = db.Column(db.String(50))
    future_opportunities = db.Column(db.String(200))
    max_applicants = db.Column(db.Integer)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    token = db.Column(db.String(200))
    expiry = db.Column(db.DateTime)

# ================= ROUTES =================
@app.route('/')
def home():
    return "Backend is running successfully 🚀"
# -------- SIGNUP --------
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json

    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if Admin.query.filter_by(email=email).first():
        return jsonify({"error": "Account already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = Admin(
        full_name=full_name,
        email=email,
        password=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Signup successful"})


# -------- LOGIN --------
@app.route('/login', methods=['POST'])
def login():
    data = request.json

    email = data.get('email')
    password = data.get('password')

    user = Admin.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        return jsonify({
            "message": "Login successful",
            "user_id": user.id
        })

    return jsonify({"error": "Invalid email or password"}), 401


# -------- FORGOT PASSWORD --------
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    # Always return same message
    response = {"message": "If email exists, reset link generated"}

    user = Admin.query.filter_by(email=email).first()

    if user:
        token = str(uuid.uuid4())
        expiry = datetime.utcnow() + timedelta(hours=1)

        reset = PasswordReset(
            email=email,
            token=token,
            expiry=expiry
        )

        db.session.add(reset)
        db.session.commit()

        print("RESET TOKEN:", token)  # for testing

    return jsonify(response)


# -------- RESET PASSWORD --------
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json

    token = data.get('token')
    new_password = data.get('password')

    reset = PasswordReset.query.filter_by(token=token).first()

    if not reset:
        return jsonify({"error": "Invalid token"}), 400

    if reset.expiry < datetime.utcnow():
        return jsonify({"error": "Token expired"}), 400

    user = Admin.query.filter_by(email=reset.email).first()

    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    db.session.commit()

    return jsonify({"message": "Password reset successful"})


# -------- ADD OPPORTUNITY --------
@app.route('/opportunities', methods=['POST'])
def add_opportunity():
    data = request.json

    required_fields = ['name', 'duration', 'start_date', 'description',
                       'skills', 'category', 'future_opportunities', 'admin_id']

    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    new_op = Opportunity(
        name=data.get('name'),
        duration=data.get('duration'),
        start_date=data.get('start_date'),
        description=data.get('description'),
        skills=data.get('skills'),
        category=data.get('category'),
        future_opportunities=data.get('future_opportunities'),
        max_applicants=data.get('max_applicants'),
        admin_id=data.get('admin_id')
    )

    db.session.add(new_op)
    db.session.commit()

    return jsonify({"message": "Opportunity created"})


# -------- GET ALL OPPORTUNITIES --------
@app.route('/opportunities/<int:admin_id>', methods=['GET'])
def get_opportunities(admin_id):
    ops = Opportunity.query.filter_by(admin_id=admin_id).all()

    result = []
    for op in ops:
        result.append({
            "id": op.id,
            "name": op.name,
            "duration": op.duration,
            "start_date": op.start_date,
            "description": op.description,
            "skills": op.skills,
            "category": op.category,
            "future_opportunities": op.future_opportunities,
            "max_applicants": op.max_applicants
        })

    return jsonify(result)


# -------- UPDATE OPPORTUNITY --------
@app.route('/opportunities/<int:id>', methods=['PUT'])
def update_opportunity(id):
    op = Opportunity.query.get(id)

    if not op:
        return jsonify({"error": "Not found"}), 404

    data = request.json

    op.name = data.get('name', op.name)
    op.duration = data.get('duration', op.duration)
    op.description = data.get('description', op.description)

    db.session.commit()

    return jsonify({"message": "Updated successfully"})


# -------- DELETE OPPORTUNITY --------
@app.route('/opportunities/<int:id>', methods=['DELETE'])
def delete_opportunity(id):
    op = Opportunity.query.get(id)

    if not op:
        return jsonify({"error": "Not found"}), 404

    db.session.delete(op)
    db.session.commit()

    return jsonify({"message": "Deleted successfully"})


# ================= RUN =================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)