import time
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
from .models import User
from . import db
import random
import string
import hashlib
import re

auth = Blueprint('auth', __name__)

def hash_password(password, salt):
    crypt = hashlib.sha512()
    crypt.update(password.encode('utf-8'))
    crypt.update(salt.encode('utf-8'))
    crypt.update(b'cBGxnhmCYWizZXjkAoMuDbVrFytfEHKlOISTsQvdqNawgeJPRL')
    return crypt.hexdigest()

def check_password(password):
    if(len(password) < 8):
        return False
    has_lowercase = False
    has_uppercase = False
    has_number = False
    has_special_char = False
    for a in password:
        if(a.isdigit()):
            has_number = True
        elif(a.islower()):
            has_lowercase = True
        elif(a.isupper()):
            has_uppercase = True
        elif(a == '!' or a == '@' or a == '#' or a == '$' or a == '%' or a == '^' or a == '&' or a == '*'):
            has_special_char = True
        else:
            return False
    return all([has_lowercase, has_uppercase, has_number, has_special_char])

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    user = User.query.filter_by(email=email).first()
    if not user or not user.password == hash_password(password, user.salt) or not check_password(password):
        time.sleep(2)
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))
    
@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    password_match = request.form.get('password_match')
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(not re.fullmatch(regex, email)):
        error = 'Incorrect email!'
        return render_template('signup.html', error=error)
    allowed = set(string.ascii_letters + string.digits + '.' + ' ')
    if(not set(name) <= allowed):
        error = 'Name can only contain letters, digits and space!'
        return render_template('signup.html', error=error)
    if(password != password_match):
        error = 'Passwords don\'t match!'
        return render_template('signup.html', error=error)
    if(not check_password(password)):
        error = 'Password needs to be at least 8 characters and include at least one: uppercase letter, lowecase letter, digit and [!, @, #, $, %, ^, &, *]'
        return render_template('signup.html', error=error)
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email address already in use!')
        return redirect(url_for('auth.signup'))
    salt = ''.join(random.sample(string.ascii_letters, 50))
    new_user = User(email=email, name=name, password=hash_password(password, salt), salt=salt)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
