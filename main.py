import re
from flask import *
import forms
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = "ChrisGayle"
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String, nullable=False)
    user = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)


db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html', current_user=current_user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.LoginForm()
    if form.validate_on_submit():
        name = form.name.data
        password = form.password.data

        user = User.query.filter_by(name=name).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('chat'))
    return render_template('login.html', form=form, current_user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        form = forms.RegisterForm()
        if form.validate_on_submit():
            name = form.name.data
            if not User.query.filter_by(name=name).first():
                hash_and_salted_password = generate_password_hash(
                    form.password.data,
                    method='pbkdf2:sha256',
                    salt_length=8
                )
                new_user = User(name=name, password=hash_and_salted_password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('chat'))
            else:
                flash("This username is in use. Please use another one.")
                return redirect(url_for('register'))
        return render_template('register.html', form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/chat', methods=['POST', 'GET'])
def chat():
    if current_user.is_authenticated:
        if request.method == "POST":
            new_message = request.form.get('message')
            date = "        " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            new = Message(message=new_message, user=current_user.name, date=date)
            db.session.add(new)
            db.session.commit()
            return redirect(url_for('chat'))
        messages = Message.query.all()
        return render_template('chat.html', messages=messages)
    else:
        return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)