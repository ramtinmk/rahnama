from flask import Flask,render_template,session,request,redirect,jsonify,send_file,url_for,flash
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import json
import sqlite3
from flask import g
import logging


# logging.basicConfig(filename='record.log', level=logging.WARNING)

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

    if "username" in session["username"]:
        is_logged = True
    app.logger.info("the user ramtin is in home")

    return render_template("home.html",is_logged=is_logged)


@app.route("/login")
def login():

    return render_template("login.html")

@app.route("/login-post",methods=["POST"])
def login_post():
    redirecting_url = "/login"
    email = request.form["email"]
    password = request.form["password"]
    
    user = query_db("select * from Users where email = ?",args=[email],one=True)
    if user and check_password_hash(user['password'], password):
        session["username"] = user["username"]
        redirecting_url = "/home"
    
    if redirecting_url == "/login":
        flash("Incorrect username or password.",category="error")
        return redirect(redirecting_url)
    
    return redirect(redirecting_url)



@app.route("/signup")
def signup():
    
    return render_template("signup.html")


@app.route("/signup-post",methods=["POST"])
def signup_post():
    has_account = False
    email = request.form["email"]
    password = request.form["password"]

    hashed_password = generate_password_hash(password)

    username = email.split("@")[0]
    user_have_account = query_db("select email from Users where email = ?",[email],one=True)

    db = get_db()
    cursor = db.cursor()

    if user_have_account is not None:
        has_account = True
    
    if not has_account:
        try:
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password))
            db.commit()

        except sqlite3.Error as e:
            app.logger.error(e)
        finally:
            db.close()
            session["username"] = username
            return redirect("/home")
    else:
        flash("the user has been already taken with this email")
        return redirect("/signup")




    

@app.route("/posts/<post_id>")
def posts(post_id):
    
    

    post = query_db("select * from posts where post_id = ?",[post_id])

    return render_template("post.html",post=post)

@app.route("/questions/ask")
def ask_question():
    
    return render_template("ask_question.html")

@app.route("/save_post", methods=['POST'])
def save_post():
    post_data = request.json
    title = post_data["title"]
    body = post_data["body"]
    tags = post_data["tags"]
    username = session["username"]

    user_id = query_db("select user_id from Users where username = ?",[username],one=True)["user_id"]

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO Posts (user_id,title,body) VALUES (?,?,?);",(user_id,title,body))
        db.commit()
    except sqlite3.Error as e:
        app.logger.error(e)
        flash(e)
    
    try: 
        post_id = query_db("select post_id from Posts where user_id = ?",[user_id],one=True)["post_id"]

        
        for tag in tags:
            tag_id = query_db("select tag_id from Tags where tag_name = ?",[tag],one=True)["tag_id"]
            cursor.execute("INSERT INTO PostTags (post_id,tag_id) VALUES (?,?);"(post_id,tag_id))
    except sqlite3.Error as e:
        app.logger.error(e)
        flash(e)
        
    redirecting_url = url_for("/posts",post_id=post_id)

    return redirect(redirecting_url)




@app.route("/questions")
def questions():
 # Get the current page number, default to 1 if not provided
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of items to show per page
    
    # Calculate the offset (how many rows to skip)
    offset = (page - 1) * per_page
    
    # Query the database to get the posts for the current page
    db = get_db()
    cursor = db.execute('SELECT * FROM posts LIMIT ? OFFSET ?', (per_page, offset))
    posts = cursor.fetchall()

    # Get the total number of posts to calculate total pages
    total_posts = db.execute('SELECT COUNT(*) FROM posts').fetchone()[0]

    total_pages = (total_posts + per_page - 1) // per_page  # Total pages

    # Render the template and pass the posts, current page, and total pages
    return render_template("questions.html", posts=posts, page=page, total_pages=total_pages) 




if __name__ == '__main__':
    app.run(debug=True)
