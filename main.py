from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# login manager contains the code that lets your application and Flask-Login work together,such as
# how to load a user from an ID, where to send users when they need to login and the like
login_manager = LoginManager()
login_manager.init_app(app)

# "user_loader" callback is used to reload the user object from the user ID stored in the session
# should take str ID of the user and return the corresponding user object
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    # CREATE TABLE IN DB
    # A mixin is simply a way to provide multiple inheritance to python
    # this is how you add a Mixin: class MyClass(MixinClassB, MixinClassA, BaseClass)
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(100), unique=True)
        password = db.Column(db.String(100))
        name = db.Column(db.String(1000))


    # db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            # user already exists
            flash("you've already signed up with this email, login instead")
            return redirect(url_for('login'))

        # hashing the password using pbkdf2:sha256 with salt length of 8
        hash_and_salted_password = generate_password_hash(
            request.form.get('password'), method='pbkdf2:sha256', salt_length=8)

        new_user = User(
           name=request.form.get('name'),
           email=request.form.get('email'),
           password=hash_and_salted_password)

        db.session.add(new_user)
        db.session.commit()

        # login and authenticate user after adding details to database
        login_user(new_user)

        return redirect(url_for('secrets'))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # find user by email entered
        user = User.query.filter_by(email=email).first()
        if user:
            # checked stored password hash against the entered password hash
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash('Password incorrect, try again')
                return redirect(url_for('login'))
        else:
            flash("this email doesn't exist, please try again")
            return redirect(url_for('login'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download', methods=['GET'])
def download():
    # access the file in the static directory(static > files > cheat_sheet.pdf) as
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
