from sqlite3 import IntegrityError
from flask import Flask, render_template, request
import db
from db import get_db
from passlib.hash import pbkdf2_sha256


app = Flask(__name__)


@app.route("/")
def hello():
	return render_template("index.html")


@app.route("/register", methods = ["GET", "POST"])
def register():
    if request.method == "POST":
        email = str(request.form.get('email'))
        if "@" not in email:
            return "invalid email"
        
        password = str(request.form.get('password'))
        passwordDuplicate = str(request.form.get('passwordDuplicate'))

        rules =[lambda s: any(x.isupper() for x in s), 
                lambda s: any(x.islower() for x in s), 
                lambda s: any(x.isdigit() for x in s),
                lambda s: any(not x.isalnum() for x in s),
                lambda s: len(s) >= 7,
                lambda s: len(s) <= 20,
                lambda s: s == passwordDuplicate                  
                ]

        if not all(rule(password) for rule in rules):
            return "password must be 7-20 characters long, have at least 1 special character, 1 digit and 1 uppercase letter"

        password = pbkdf2_sha256.hash(password)
        

        db = get_db()
        
        try: 
            db.execute("insert into users(email, password) values(?, ?)", (email, password))
            db.commit()
        except IntegrityError:
            db.rollback()
        
        return "check your email and validate your account"

    else:
        return render_template("register.html")



@app.route("/login", methods = ["GET", "POST"])
def login():
    if request.method == "POST":
        email = str(request.form.get('email'))
        password = str(request.form.get('password'))

        db = get_db()
        try:
            query = db.execute("select password from users where email = ? " , (email, )).fetchall()
            if len(query) == 1 and pbkdf2_sha256.verify(password, query[0][0]):
                return "Welcome " + email
            else:
                return "Invalid credentials"
        except Exception as e:
            print(e)
            return render_template("index.html")

    else:
        return render_template("login.html")


if __name__ == "__main__":
    app.run()
    with app.app_context():
        db.init_app(app)
