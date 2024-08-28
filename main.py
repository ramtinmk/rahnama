from flask import Flask,render_template,session,request,redirect,jsonify,send_file,url_for,flash
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
import json
import logging
from database_utils import *
from flask import g
import re
from flask_oauthlib.client import OAuth

app = Flask(__name__)


google_client_id = '752114163217-acou1eavo31s8d71lbfb89l568b9bjck.apps.googleusercontent.com'
google_client_secret = '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'
google_redirect_uri = 'your_google_redirect_uri_here'
# Google OAuth Configuration
oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=google_client_id,
    consumer_secret=google_client_secret,
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('data/schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def is_valid_email(email: str) -> bool:
    # Regular expression for validating an Email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    
    # Returns True if the string matches the email pattern, else False
    return re.match(email_regex, email) is not None



app.secret_key = secrets.token_hex(16)


@app.route("/")
@app.route("/home")
def home():
    is_logged = False
    username = None
    if "email" in session:
        is_logged = True
        username = query_db("select username from Users where email = ?",args=[session["email"]],one=True)
        if username is None:
            username = session["email"].split("@")[0]
        else:
            username = username["username"]
        session["username"] = username
    else:
        if "username" in session:
            is_logged = True
            username = session["username"]
    app.logger.info("the user ramtin is in home")

    return render_template("home.html",is_logged=is_logged,username=username)


@app.route("/login")
def login():

    return render_template("login.html")

@app.route("/login-post",methods=["POST"])
def login_post():
    redirecting_url = "/login"
    

    input = request.form["email_or_username"]

    is_email = is_valid_email(input)

    password = request.form["password"]
    if is_email:
        user = query_db("select * from Users where email = ?",args=[input],one=True)
    else:
        user = query_db("select * from Users where username = ?",args=[input],one=True)
    
    if user and check_password_hash(user['password'], password):
        session["username"] = user["username"]
        redirecting_url = "/home"
    
    if redirecting_url == "/login":
        flash("Incorrect username or password.",category="error")
        return redirect(redirecting_url)
    return redirect(redirecting_url)

@app.route("/redirect_auth")
def redirect_auth():
    return google.authorize(callback=url_for('auth', _external=True))

@app.route('/auth/callback')
def auth():

    # This route handles the callback from Google OAuth
    response = google.authorized_response()
    session['google_token'] = (response['access_token'], '')
    
    if response is None or response.get('access_token') is None:
        return 'Login failed.'

   
    me = google.get('userinfo')
    # Store user info in session
    session['email'] = me.data["email"]
    
    return redirect('/')

@app.route("/signup")
def signup():
    
    return render_template("signup.html")


@app.route("/signup-post",methods=["POST"])
def signup_post():
    has_account = False
    username = request.form["Username"]
    email = request.form["email"]
    password = request.form["password"]

    hashed_password = generate_password_hash(password)

    user_have_account = query_db("select email from Users where email = ?",[email],one=True)

    db = get_db()
    cursor = db.cursor()

    if user_have_account is not None:
        has_account = True
    
    if not has_account:
        try:
            cursor.execute('INSERT INTO Users (username, email, password) VALUES (?, ?, ?)',
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
    
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of items to show per page

    offset = (page - 1) * per_page

    post = query_db("select * from Posts where post_id = ?",[post_id],one=True)
    
    comments = query_db("select * from Comments where post_id = ? limit ? offset ?",[post_id,per_page,offset])
    # Get the total number of posts to calculate total pages
    total_comments = query_db('SELECT COUNT(*) as count FROM Comments where post_id = ?',[post_id],one=True)["count"]

    user_posted_id =  query_db("select user_id from Posts where post_id = ?",args=[post_id],one=True)["user_id"]

    username_posted = query_db("select username from Users where user_id = ?",args=[user_posted_id],one=True)["username"]

    tag_ids = query_db("select tag_id from PostTags where post_id = ?",args=[post_id])
    tags = []
    for id in tag_ids:
        tags.append(query_db("select tag_name from Tags where tag_id = ?",args=[id["tag_id"]],one=True)["tag_name"])

    upvote_count = query_db("select COUNT(*) as upvote_count from Votes where post_id = ?",[post_id],one=True)["upvote_count"]

    print(upvote_count)


    total_pages = (total_comments+ per_page - 1) // per_page  # Total pages

    try:
        return render_template("post.html",post=post,username=username_posted,tags=tags,upvote_count=upvote_count)
    except Exception as e:
        print(f"Error rendering template: {e}")
        return "Failed to render template", 500

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

    user_id = query_db("SELECT user_id FROM Users WHERE username = ?", [username], one=True)["user_id"]

    db = get_db()
    cursor = db.cursor()
    try:
        # Insert the post
        cursor.execute("INSERT INTO Posts (user_id, title, body) VALUES (?, ?, ?);", (user_id, title, body))
        db.commit()
        
        # Get the post_id of the newly inserted post
        post_id = query_db("SELECT MAX(post_id) as new_post_id FROM Posts", one=True)["new_post_id"]
        
        # Insert tags
        for tag in tags:
            tag_id = query_db("SELECT tag_id FROM Tags WHERE tag_name = ?", [tag], one=True)["tag_id"]
            cursor.execute("INSERT INTO PostTags (post_id, tag_id) VALUES (?, ?);", (post_id, tag_id))
        
        db.commit()

    except sqlite3.Error as e:
        db.rollback()
        app.logger.error(e)
        return jsonify({"error": str(e)}), 500

    # Return the post_id as a JSON response
    return jsonify({"post_id": post_id})




@app.route("/questions")
def questions():
 # Get the current page number, default to 1 if not provided
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of items to show per page
    
    # Calculate the offset (how many rows to skip)
    offset = (page - 1) * per_page
    
    # Query the database to get the posts for the current page
    # print(per_page,offset)
    db = get_db()
    cursor = db.cursor()
    posts = cursor.execute('SELECT * FROM Posts LIMIT ? OFFSET ?', (per_page, offset)).fetchall()

    # Get the total number of posts to calculate total pages
    total_posts = db.execute('SELECT COUNT(*) as count FROM Posts').fetchone()['count']
    total_pages = (total_posts + per_page - 1) // per_page  # Total pages

    print(posts)
    # Render the template and pass the posts, current page, and total pages
    return render_template("questions.html", posts=posts, page=page, total_pages=total_pages) 


@app.route("/myquestions")
def myquestions():
    username = session["username"]

    user_id = query_db("SELECT user_id FROM Users WHERE username = ?", [username], one=True)["user_id"]

    my_posts = query_db("SELECT * from Posts WHERE user_id = ?",args=[user_id])

    return render_template("myquestions.html",posts = my_posts)

@app.route("/upvote",methods=["POST"])
def upvote():
    data = request.json

    username = session["username"]
    post_id = data["post_id"]
    vote_type = "upvote"

    user_id = query_db("select user_id from Users where username = ?",[username],one=True)["user_id"]
    db = get_db()
    cursor = db.cursor()

    print(user_id,post_id,vote_type)
    try:
        cursor.execute("INSERT INTO Votes (post_id,user_id,vote_type) VALUES (?,?,?);",(post_id,user_id,vote_type))
        db.commit()
        
    except sqlite3.Error as e:
        app.logger.error(e)
        flash(e)
        return jsonify({"error":e})
    finally:
        db.close()
    
    return jsonify({"status":"ok"})

        


@app.route("/search")
def search():
    
    search_parameter = request.args["search_word"]

    search_result = query_db(f"select * from Posts where body like '%{search_parameter}%' or title like '%{search_parameter}%'",one=False)


    return render_template("search_result.html",posts=search_result)


@app.route("/yourprofile")
def yourprofile():
    is_logged = False

    if "username" in session:
        username = session["username"]
        email = query_db("select email from Users where username = ?",[username],one=True)["email"]
        is_logged = True

    return render_template("myprofile.html",username=username,email=email,is_logged=is_logged)

@app.route("/profile/update",methods=['POST'])
def profile_update():
    username = request.form["username"]
    email = request.form["email"]
    db = get_db()
    cursor = db.cursor()

    old_username = session["username"]
    print(session["username"],username)
    if session["username"]!= username:
        try:
           cursor.execute(f"UPDATE Users SET username=? WHERE username=? ;",(username,old_username))
           db.commit()

        except sqlite3.Error as e:
            print(e)
        session["username"] = username

    old_email = query_db(f"select email from Users where username = '{old_username}'  ;",one=True)

    print(old_email,email)
    if old_email!=email:
        try:
            cursor.execute("UPDATE Users SET email =? WHERE username =?;", (email, old_username))
            db.commit()
        except sqlite3.Error as e:
            print(e)

    return redirect("/yourprofile")


@app.route("/logout")
def logout():
    session.pop("username","")
    session.pop("email","")
    return redirect("/home")

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

if __name__ == '__main__':
    app.run(debug=True)
