from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import os
import bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)

# -------------------------------
# CONFIG
# -------------------------------
app.config['SECRET_KEY'] = 'secret123'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -------------------------------
# ENCRYPTION KEY
# -------------------------------
key_path = os.path.join(basedir, 'secret.key')
if os.path.exists(key_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

cipher = Fernet(key)

# -------------------------------
# MODELS
# -------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# -------------------------------
# HOME
# -------------------------------
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

# -------------------------------
# REGISTER
# -------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash("All fields required", "error")
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists", "error")
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registered Successfully", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# -------------------------------
# LOGIN
# -------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.checkpw(password.encode(), user.password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid login", "error")

    return render_template('login.html')

# -------------------------------
# DASHBOARD
# -------------------------------
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')

        encrypted_password = cipher.encrypt(password.encode())

        new_entry = Password(
            website=website,
            username=username,
            password=encrypted_password,
            user_id=session['user_id']
        )

        db.session.add(new_entry)
        db.session.commit()

        flash("Saved!", "success")

    data = Password.query.filter_by(user_id=session['user_id']).all()

    # Decrypt passwords before sending
    passwords = []
    for p in data:
        decrypted = cipher.decrypt(p.password).decode()
        passwords.append({
            'id': p.id,
            'website': p.website,
            'username': p.username,
            'password': decrypted
        })

    return render_template('dashboard.html', passwords=passwords)

# -------------------------------
# DELETE
# -------------------------------
@app.route('/delete/<int:id>')
def delete(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    entry = Password.query.get(id)
    if not entry or entry.user_id != session['user_id']:
        flash("Entry not found", "error")
        return redirect(url_for('dashboard'))
    
    db.session.delete(entry)
    db.session.commit()
    flash("Deleted!", "success")
    return redirect(url_for('dashboard'))

# -------------------------------
# EDIT
# -------------------------------
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    entry = Password.query.get(id)
    if not entry or entry.user_id != session['user_id']:
        flash("Entry not found", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entry.website = request.form.get('website')
        entry.username = request.form.get('username')

        new_password = request.form.get('password')
        entry.password = cipher.encrypt(new_password.encode())

        db.session.commit()
        flash("Updated!", "success")
        return redirect(url_for('dashboard'))

    decrypted_password = cipher.decrypt(entry.password).decode()

    return render_template('edit.html', entry=entry, password=decrypted_password)

# -------------------------------
# LOGOUT
# -------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -------------------------------
# RUN
# -------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
