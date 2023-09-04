from flask import Flask, render_template, request , url_for, redirect,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'  
app.secret_key = 'wqe3rf32422dsaw'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.route('/dashboard.html', methods=['GET', 'POST'])
@login_required
def dashboard():
    lectures = Lectures.query.filter_by(Teacher=current_user.username).all()
    return render_template('dashboard.html', lectures=lectures)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
  db.create_all()


  return render_template("home.html")



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)




@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



class Courses(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(255))
    course_batch = db.Column(db.String(255))
    course_description = db.Column(db.String(255))
    course_level = db.Column(db.String(255))

class Lectures(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date)  
    Teacher = db.Column(db.String(255))
    course_name = db.Column(db.String(255))

@app.route('/AdminDashboard.html', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    return render_template('AdminDashboard.html')


@app.route('/AddCourse.html', methods=['POST','GET'])
def get_courseInfo():
    if request.method == 'POST':
        course_name = request.form['course_name']
        course_batch = request.form['course_batch']
        course_description = request.form['course_description']
        course_level = request.form['course_level']

        course = Courses(
            course_name=course_name,
            course_batch=course_batch,
            course_description=course_description,
            course_level=course_level
        )
        db.session.add(course)
        db.session.commit()
 
    return render_template('AddCourse.html')




@app.route('/AssignCourse.html', methods=['GET', 'POST'])
def assign_course():
    if request.method == 'POST':
        course_name = request.form['course_name']
        teacher_name = request.form['Names']
        date_str = request.form['date']
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Check if a lecture already exists on the selected date
        existing_lecture = Lectures.query.filter_by(date=date).first()
        if existing_lecture:
            flash('A lecture is already assigned on this date.')
        else:
            existing_user_lecture = Lectures.query.filter_by(Teacher=teacher_name, date=date).first()
            if existing_user_lecture:
                flash('This user already has a lecture on this date.')
            else:
                lecture = Lectures(
                    course_name=course_name,
                    Teacher=teacher_name,
                    date=date
                )
                db.session.add(lecture)
                db.session.commit()
                flash('Lecture assigned successfully.')

    courses = Courses.query.all()
    names = User.query.all()
    return render_template('AssignCourse.html', courses=courses, Names=names)

    
    











if __name__ == '__main__':
    app.run(debug=True)