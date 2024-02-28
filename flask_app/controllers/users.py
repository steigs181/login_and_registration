from flask_app import app
from flask import render_template, request, redirect, session, flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app) 

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/register', methods=['POST'])
def register_user():
    if not User.validate_user(request.form):
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print (pw_hash)
    agree_to_terms = int(request.form.get('agree_to_terms', 0))
    data = {
        'email': request.form['email'],
        'password': pw_hash,
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'gender': request.form['gender'],
        'agree_to_terms': agree_to_terms
    }
    user_id = User.save_user(data)
    session['user_id'] = user_id
    return redirect('/success')

@app.route('/login', methods=['POST'])
def login():
    data = {
        'email': request.form['email']
    }
    user_in_db = User.get_by_email(data)
    if not user_in_db:
        flash('invalid email or password')
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        flash('Invalid password')
        return redirect('/')
    session["user_id"] = user_in_db.id
    return redirect('/success')

@app.route('/success')
def user_dashboard():
    user = User.get_one_by_id(session['user_id'])
    return render_template('success.html', user = user)

@app.route('/logout', methods=["POST"])
def user_logout():
    session.clear()
    return redirect('/')