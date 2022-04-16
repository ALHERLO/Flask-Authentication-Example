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
def load_user(user_id):
    return User.query.get(int(user_id))

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
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods = ["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        password = request.form.get("password")

        hashed_password = generate_password_hash(password, method = "pbkdf2:sha256", salt_length = 5)
        email = request.form.get("email")
        user_exists = user = User.query.filter_by(email=email).first()
        if user_exists:
            error = "Password already exist. Try a new one or login."
            return render_template("register.html", error=error)
        new_user = User(
            email=request.form.get("email"),
            password = hashed_password,
            name = request.form.get("name")
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        logged_in = True
        return render_template("secrets.html", logged_in=current_user.is_authenticated, name=new_user.name)
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        print(user)

        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password): #returns True
                print("Passwords Match")
                login_user(user)
                logged_in = True
                return redirect(url_for('secrets')  )
            else:
                print("invalid password")
                error = 'Invalid Password!'
                return render_template("login.html", error=error)
        else:
            error = 'Email not found in records'
            return render_template("login.html", error = error)
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", logged_in=current_user.is_authenticated, name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home', logged_in=current_user.is_authenticated))


@app.route('/download')
@login_required           # Importante Login required decorator
def download():
    return send_from_directory('static', filename='files/cheat_sheet.pdf')
                               # ,as_attachment=True) #this is to download the file



if __name__ == "__main__":
    app.run(debug=True)
