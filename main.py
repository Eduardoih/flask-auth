from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def get_user(user_id):
    return User.query.filter_by(id=user_id).first()


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form['email']).first() is None:
            password_raw = request.form['password']
            encrypted = generate_password_hash(password_raw, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                email=request.form['email'],
                password=encrypted,
                name=request.form['name']
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return render_template("secrets.html")
        else:
            flash("This email already exists on our database.")
            return render_template("register.html")
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return render_template("secrets.html")
            else:
                flash("Incorrect password, please try again.")
                return render_template("login.html")
        else:
            flash("That email does not exist, please try again.")
            return render_template("login.html")
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/download')
@login_required
def download():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    return send_from_directory("static/files/", "cheat_sheet.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
