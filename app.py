from flask import Flask, url_for, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, form
from flask_login import UserMixin, login_user , LoginManager, login_required, logout_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app=app)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///data.db'
app.config["SECRET_KEY"] = "THISISSECRET"


#log in manger ----------------------------------------------------------------------------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
# ------------------------------------------------------------------------------------------------------------



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

     
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String(50), nullable=False)
    school_id = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Singup(FlaskForm):
    school_id = StringField(validators=[InputRequired(), Length(min=4, max=10)], render_kw={"placeholder": "School Id"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    cpassword =PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm Password"})
    school_name = StringField(validators=[InputRequired(), Length(max=50)], render_kw={"placeholder": "School Name"})
    submit = SubmitField("singup")

    def validate_school_id(self, school_id):
        existing_school = User.query.filter_by(school_id=school_id.data).first()
        if existing_school:
            note = "User Already Exists"
        else:note = ""
    def check_password(self, password, cpassword):
        if password == cpassword:
            return True

class Login(FlaskForm):
    school_id = StringField(validators=[InputRequired(), Length(min=4, max=10)], render_kw={"placeholder": "School Id"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField("LOGIN")


@app.route('/')
def home():
    return render_template('/Home Page/Home.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    form = Login()
    msg = ''
    if form.validate_on_submit():
        user = User.query.filter_by(school_id = form.school_id.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template('dash.html')

        msg = "Invalid Username or Password"
    return render_template("login.html", form=form, msg=msg)


@app.route('/signup', methods=["GET", "POST"])
def signup():
    form = Singup()
    note = ''
    if form.validate_on_submit():
        if form.check_password(form.password.data, form.cpassword.data):
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(school_id=form.school_id.data, school_name=form.school_name.data, password = hashed_password)
            db.session.add(new_user)
            print("User Added")
            db.session.commit()
            return redirect("login")

        else:
            note = "Passwords Don't match or user Already Exists"

    return render_template('signup.html', form=form, note = note)


@app.route('/dash', methods = ["POST", "GET"])
@login_required
def dash():
    return redirect('dash.html')

@app.route('/logout', methods = ["POST", "GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

    


if __name__ == '__main__':
    app.run(debug=True, host= "192.168.55.104")

