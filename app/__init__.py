from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import os
from PIL import Image
import glob
import shutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\OM SAI\\desktop\\encrypt_decrypt_app\\database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/success', methods=['GET', 'POST'])
def success():
    
    if request.method == 'POST':
        f = request.files['file']
        f.save('upload/' + secure_filename(f.filename))
        for count,filename in enumerate(os.listdir("upload")):
            dst = "flower" + ".png"
            src = 'upload/' + filename
            dst = 'upload/' + dst
            os.rename(src,dst)
            return render_template('dashboard.html')
        
@app.route("/encryption")
def encryption():
    
    image = Image.open("upload/flower.png")
    color_image = image.convert('CMYK')
    bw_image = image.convert('1')



    outfile1 = Image.new("CMYK", [dimension for dimension in image.size])

    outfile2 = Image.new("CMYK", [dimension for dimension in image.size])

    outfile3 = Image.new("CMYK", [dimension for dimension in image.size])



    for x in range(0, image.size[0], 1):
        for y in range(0, image.size[1], 1):
            sourcepixel = image.getpixel((x, y))

            outfile1.putpixel((x, y),(sourcepixel[0],0,0,0))

            outfile2.putpixel((x, y),(0,sourcepixel[1],0,0))

            outfile3.putpixel((x, y),(0,0,sourcepixel[2],0))


    outfile1.save('ephoto/out1.jpg')
    
    outfile2.save('ephoto/out2.jpg')
    outfile3.save('ephoto/out3.jpg')



    image1 = Image.open("ephoto/out1.jpg")
    image2 = Image.open("ephoto/out2.jpg")
    image3 = Image.open("ephoto/out3.jpg")

    image1 = image1.convert('1')
    image2 = image2.convert('1')
    image3 = image3.convert('1')

    hf1 = Image.new("CMYK", [dimension for dimension in image1.size])
    hf2 = Image.new("CMYK", [dimension for dimension in image1.size])
    hf3 = Image.new("CMYK", [dimension for dimension in image1.size])

    for x in range(0, image1.size[0]):
        for y in range(0, image1.size[1]):
            pixel_color1 = image1.getpixel((x, y))
            pixel_color2 = image2.getpixel((x, y))
            pixel_color3 = image3.getpixel((x, y))
            if pixel_color1 == 255:
                hf1.putpixel((x, y),(255,0,0,0))
            else:
                hf1.putpixel((x, y),(0,0,0,0))

            if pixel_color2 == 255:
                hf2.putpixel((x, y),(0,255,0,0))
            else:
                hf2.putpixel((x, y),(0,0,0,0))

            if pixel_color3 == 255:
                hf3.putpixel((x, y),(0,0,255,0))
            else:
                hf3.putpixel((x, y),(0,0,0,0))



    hf1.save('ephoto/hf1.jpg')
    hf2.save('ephoto/hf2.jpg')
    hf3.save('ephoto/hf3.jpg')




    image1 = Image.open("ephoto/hf1.jpg")
    image1 = image1.convert('CMYK')

    image2 = Image.open("ephoto/hf2.jpg")
    image2 = image2.convert('CMYK')

    image3 = Image.open("ephoto/hf3.jpg")
    image3 = image3.convert('CMYK')


    share1 = Image.new("CMYK", [dimension * 2 for dimension in image1.size])

    share2 = Image.new("CMYK", [dimension * 2 for dimension in image2.size])

    share3 = Image.new("CMYK", [dimension * 2 for dimension in image3.size])




    for x in range(0, image1.size[0]):
        for y in range(0, image1.size[1]):
            pixelcolor = image1.getpixel((x, y))

            if pixelcolor[0]+pixelcolor[1]+pixelcolor[2] == 0:
                share1.putpixel((x * 2, y * 2), (255,0,0,0))
                share1.putpixel((x * 2 + 1, y * 2), (0,0,0,0))
                share1.putpixel((x * 2, y * 2 + 1), (0,0,0,0))
                share1.putpixel((x * 2 + 1, y * 2 + 1), (255,0,0,0))

            else:
                share1.putpixel((x * 2, y * 2), (0,0,0,0))
                share1.putpixel((x * 2 + 1, y * 2), (255,0,0,0))
                share1.putpixel((x * 2, y * 2 + 1), (255,0,0,0))
                share1.putpixel((x * 2 + 1, y * 2 + 1), (0,0,0,0))

            pixelcolor = image2.getpixel((x, y))

            if pixelcolor[0]+pixelcolor[1]+pixelcolor[2] == 0:
                share2.putpixel((x * 2, y * 2), (0,255,0,0))
                share2.putpixel((x * 2 + 1, y * 2), (0,0,0,0))
                share2.putpixel((x * 2, y * 2 + 1), (0,0,0,0))
                share2.putpixel((x * 2 + 1, y * 2 + 1), (0,255,0,0))

            else:
                share2.putpixel((x * 2, y * 2), (0,0,0,0))
                share2.putpixel((x * 2 + 1, y * 2), (0,255,0,0))
                share2.putpixel((x * 2, y * 2 + 1), (0,255,0,0))
                share2.putpixel((x * 2 + 1, y * 2 + 1), (0,0,0,0))

            pixelcolor = image3.getpixel((x, y))

            if pixelcolor[0]+pixelcolor[1]+pixelcolor[2] == 0:
                share3.putpixel((x * 2, y * 2), (0,0,255,0))
                share3.putpixel((x * 2 + 1, y * 2), (0,0,0,0))
                share3.putpixel((x * 2, y * 2 + 1), (0,0,0,0))
                share3.putpixel((x * 2 + 1, y * 2 + 1), (0,0,255,0))

            else:
                share3.putpixel((x * 2, y * 2), (0,0,0,0))
                share3.putpixel((x * 2 + 1, y * 2), (0,0,255,0))
                share3.putpixel((x * 2, y * 2 + 1), (0,0,255,0))
                share3.putpixel((x * 2 + 1, y * 2 + 1), (0,0,0,0))



    share1.save('ephoto/share1.jpg')
    share2.save('ephoto/share2.jpg')
    share3.save('ephoto/share3.jpg')
    os.remove("dphoto/final.jpg")

    return render_template('dashboard.html')

@app.route("/decryption")
def decryption():

    infile1 = Image.open("ephoto/share1.jpg")
    infile2 = Image.open("ephoto/share2.jpg")
    infile3 = Image.open("ephoto/share3.jpg")

    outfile = Image.new('CMYK', infile1.size)

    for x in range(0,infile1.size[0],2):
        for y in range(0,infile1.size[1],2):

            C = infile1.getpixel((x+1, y))[0]
            M = infile2.getpixel((x+1, y))[1]
            Y = infile3.getpixel((x+1, y))[2]


            outfile.putpixel((x, y), (C,M,Y,0))
            outfile.putpixel((x+1, y), (C,M,Y,0))
            outfile.putpixel((x, y+1), (C,M,Y,0))
            outfile.putpixel((x+1, y+1), (C,M,Y,0))
    

    outfile.save("dphoto/final.jpg")
    os.remove("upload/flower.png")
    files = glob.glob('ephoto/**/*.jpg',recursive=True)
    for f in files:
        try:
            os.remove(f)
        except OSError as e:
            print("Error:%s:%s"%(f,e.strerror))
    img = Image.open(r"dphoto/final.jpg")
    img.show()
    
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

def getApp():
    return app
