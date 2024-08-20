from flask import Flask,render_template,session,request,redirect,jsonify,send_file,url_for,flash
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import json
import sqlite3
from flask import g

app = Flask(__name__)



app.secret_key = secrets.token_hex(16)

DATABASE = 'data/database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = make_dicts

    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('data/schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))

@app.route("/")
@app.route("/home")
def home():
    is_logged = False

    # if "username" in session["username"]:
    #     is_logged = True
    
    return render_template("home.html",is_logged=is_logged)


@app.route("/login")
def login():

    return render_template("login.html")

@app.route("/login-post",methods=["POST"])
def login_post():
    username = request.form["fname"]

    password = request.form["lname"]

    return f"{username} , {password} login"


@app.route("/signup")
def signup():
    
    return render_template("signup.html")


@app.route("/signup-post",methods=["POST"])
def signup_post():
    name = request.form["fname"]
    last_name = request.form["lname"]

    return f"{name} {last_name}"

@app.route("/posts/<post_id>")
def posts():
    pass





if __name__ == '__main__':
    app.run(debug=True)
