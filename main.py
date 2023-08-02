from flask import Flask,render_template,request,flash,url_for,redirect
import os
import cv2
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager , login_required, logout_user, current_user
from wtforms import StringField ,PasswordField, SubmitField
from flask_wtf import RecaptchaField
from wtforms.validators import InputRequired,length,ValidationError
from flask_wtf import FlaskForm 
from flask_bcrypt import Bcrypt 
from sqlalchemy.exc import SQLAlchemyError
import numpy as np
from wtforms.validators import InputRequired, Email, Length
from wtforms import StringField, TextAreaField, SubmitField


UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'webp', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# app.config['SECRET_KEY']='supersecretkey'
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcGRG0nAAAAAHnYU-RVfbjd4glt2CNdAW_Up_td'

app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcGRG0nAAAAALEaSVbjIhk9sFsVeY3yveCVZtsV'




db = SQLAlchemy(app)
bcrypt=Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False , unique=True)
    password = db.Column(db.String(80), nullable=False)



class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)



with app.app_context():
 db.create_all()

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(),length(min=4,max=20)],render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(),length(min=4,max=20)],render_kw={"placeholder": "Password"})
    Submit = SubmitField("Register")

    def validate_username(self,username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError(
                "That Username already exists.Please Choose a different one"
            )
        

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),length(min=4,max=20)],render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(),length(min=4,max=20)],render_kw={"placeholder": "Password"})
    Submit = SubmitField("Login")
    recaptcha=RecaptchaField()

class ContactForm(FlaskForm):
    name = StringField('Your Name', validators=[InputRequired(), Length(max=100)])
    email = StringField('Your Email', validators=[InputRequired(), Email()])
    subject = StringField('Subject', validators=[InputRequired(), Length(max=200)])
    message = TextAreaField('Message', validators=[InputRequired()])
    submit = SubmitField('Send Message')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def processImage(filename,operation):
    print(f"the operation is {operation} and filename is {filename}")
    img=cv2.imread(f"uploads/{filename}")
    match operation:
        case"cgray":
            imgProcessed=cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            newFilename =f"static/{filename}"
            cv2.imwrite(newFilename,imgProcessed)
            return newFilename
        
        case"cwebp":
            newFilename= f"static/{filename.split('.')[0]}.webp"
            cv2.imwrite(newFilename,img)
            return newFilename
        

        case"cpng":
            newFilename= f"static/{filename.split('.')[0]}.png"
            cv2.imwrite(newFilename,img)
            return newFilename
        

        case"cjpg":
            newFilename= f"static/{filename.split('.')[0]}.jpg"
            cv2.imwrite(newFilename,img)
            return newFilename
        
        case "rotate90":
            (h, w) = img.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, 90, 1.0)
            imgRotated = cv2.warpAffine(img, M, (w, h))
            newFilename = f"static/{filename.split('.')[0]}_rotated90.jpg"
            cv2.imwrite(newFilename, imgRotated)
            return newFilename
        
        case "blur":
            imgBlurred = cv2.GaussianBlur(img, (25, 25), 0)  # Adjust the kernel size (25, 25) as needed
            newFilename = f"static/{filename.split('.')[0]}_blurred.jpg"
            cv2.imwrite(newFilename, imgBlurred)
            return newFilename
        
        case "sharpen":
            kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])  # Sharpening kernel
            imgSharpened = cv2.filter2D(img, -1, kernel)
            newFilename = f"static/{filename.split('.')[0]}_sharpened.jpg"
            cv2.imwrite(newFilename, imgSharpened)
            return newFilename

        case "resize":
            resized_img = cv2.resize(img, (60, 60))
            newFilename = f"static/{filename.split('.')[0]}_resized.jpg"
            cv2.imwrite(newFilename, resized_img)
            return newFilename
           
    pass

@app.route("/",methods =['GET','POST'])
@login_required
def home():
    return render_template("index.html")


@app.route("/login",methods =['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                print("Redirecting to home page")
                return redirect(url_for('home'))
    return render_template("login.html",form=form)


@app.route("/register",methods =['GET','POST'])
def register():
    form=RegistrationForm()


    if form.validate_on_submit():
        hashed_password =bcrypt.generate_password_hash(form.password.data)
        new_user=User(username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html",form=form)


 
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()  # Create an instance of the ContactForm

    if form.validate_on_submit():
        # Extract data from the form
        name = form.name.data
        email = form.email.data
        subject = form.subject.data
        message = form.message.data

        # Save the form data to the database
        new_message = ContactMessage(name=name, email=email, subject=subject, message=message)
        db.session.add(new_message)
        db.session.commit()

        flash("Your message has been sent successfully!", "success")
        return redirect(url_for('contact'))

    return render_template("contact.html", form=form)

@app.route("/edit",methods=["GET","POST"])
def edit():
    if request.method=="POST":
        operation = request.form.get("operation")
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return "error" 
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return "error no selected file"
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new = processImage(filename,operation)
            flash(f"Image is processed and available <a href ='/{new}'target='_blank'> here</a>")
            return render_template("index.html")
        


    return render_template("about.html")


if __name__ == "__main__":

 app.run(debug=True ,port=5002)