import re
import secrets
from datetime import datetime, timedelta

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
    make_response,
    abort
)
from flask_oauthlib.client import OAuth
from werkzeug.security import check_password_hash, generate_password_hash

from flasgger import Swagger
import os

from database_utils import *

app = Flask(__name__)

language = "persian"


swagger_config_path =os.getcwd()+"\\"+ "static"+  "\\" + os.path.join("swagger", "config.yaml")

swagger = Swagger(app, template_file=swagger_config_path.replace("\\","/"))

google_client_id = (
    "752114163217-acou1eavo31s8d71lbfb89l568b9bjck.apps.googleusercontent.com"
)
google_client_secret = "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"
google_redirect_uri = "your_google_redirect_uri_here"
# Google OAuth Configuration
oauth = OAuth(app)
google = oauth.remote_app(
    "google",
    consumer_key=google_client_id,
    consumer_secret=google_client_secret,
    request_token_params={
        "scope": "email",
    },
    base_url="https://www.googleapis.com/oauth2/v1/",
    request_token_url=None,
    access_token_method="POST",
    access_token_url="https://accounts.google.com/o/oauth2/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
)


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource("data/schema.sql", mode="r") as f:
            db.cursor().executescript(f.read())
        db.commit()


def is_valid_email(email: str) -> bool:
    # Regular expression for validating an Email
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

    # Returns True if the string matches the email pattern, else False
    return re.match(email_regex, email) is not None


def time_ago(datetime_str):
    # Convert the datetime string to a datetime object
    past_time = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S") + timedelta(
        hours=3, minutes=30
    )

    # Get the current time
    now = datetime.now()

    # Calculate the difference
    time_difference = now - past_time

    # Calculate the seconds difference
    seconds = time_difference.total_seconds()

    # Convert seconds to minutes, hours, days, etc.
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{int(minutes)} minutes ago"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{int(hours)} hours ago"
    elif seconds < 2592000:
        days = seconds // 86400
        return f"{int(days)} days ago"
    elif seconds < 31536000:
        months = seconds // 2592000
        return f"{int(months)} months ago"
    else:
        years = seconds // 31536000
        return f"{int(years)} years ago"


def check_is_logged():
    return "username" in session


app.secret_key = secrets.token_hex(16)

@app.errorhandler(404)
def not_found(error):
    resp = make_response(render_template('persian/404.html'), 404)
    resp.headers['X-Something'] = 'A value'
    return resp


@app.route("/")
@app.route("/home")
def home():
    is_logged = False
    username = None
    if "email" in session:
        is_logged = True
        username = query_db(
            "select username from Users where email = ?",
            args=[session["email"]],
            one=True,
        )
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

    return render_template(f"{language}/home.html", is_logged=is_logged, username=username)


@app.route("/login")
def login():
    return render_template(f"{language}/login.html")


@app.route("/login-post", methods=["POST"])
def login_post():
    redirecting_url = "/login"
    input = request.form["email_or_username"]

    is_email = is_valid_email(input)

    password = request.form["password"]
    try:
        if is_email:
            user = query_db("select * from Users where email = ?", args=[input], one=True)
        else:
            user = query_db(
                "select * from Users where username = ?", args=[input], one=True
            )

        if user and check_password_hash(user["password"], password):
            session["username"] = user["username"]
            redirecting_url = "/home"

        if redirecting_url == "/login":
            flash("Incorrect username or password.", category="error")
            return redirect(redirecting_url),401
        return redirect(redirecting_url)
    except Exception:
        return "Internal server error", 500


@app.route("/redirect_auth")
def redirect_auth():
    return google.authorize(callback=url_for("auth", _external=True))


@app.route("/auth/callback")
def auth():
    # This route handles the callback from Google OAuth
    response = google.authorized_response()
    session["google_token"] = (response["access_token"], "")

    if response is None or response.get("access_token") is None:
        return "Login failed."

    me = google.get("userinfo")
    # Store user info in session
    session["email"] = me.data["email"]

    return redirect("/")


@app.route("/signup")
def signup():
    return render_template(f"{language}/signup.html")


@app.route("/signup-post", methods=["POST"])
def signup_post():
    has_account = False
    username = request.form["Username"]
    email = request.form["email"]
    password = request.form["password"]

    hashed_password = generate_password_hash(password)

    try:
        user_have_account = query_db(
            "select email from Users where email = ?", [email], one=True
        )

        db = get_db()
        cursor = db.cursor()

        if user_have_account is not None:
            has_account = True

        if not has_account:
            try:
                cursor.execute(
                    "INSERT INTO Users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password),
                )
                db.commit()

            except sqlite3.Error as e:
                app.logger.error(e)
            finally:
                db.close()
                session["username"] = username
                return redirect("/home")
        else:
            flash("the user has been already taken with this email")
            return redirect("/signup"),401
    except Exception:
        return "Internal server error",500


@app.route("/posts/<post_id>")
def posts(post_id):
    page = request.args.get("page", 1, type=int)
    per_page = 5  # Number of items to show per page

    offset = (page - 1) * per_page

    try:
        post = query_db("select * from Posts where post_id = ?", [post_id], one=True)
        if post is None:
            return render_template(f"{language}/404.html")

        comments = query_db(
            "select * from Comments where post_id = ? ORDER BY created_at DESC limit ? offset ?",
            [post_id, per_page, offset],
        )

        for comment in comments:
            commentor_username = query_db(
                "select username from Users where user_id = ?",
                [comment["user_id"]],
                one=True,
            )["username"]
            comment["username"] = commentor_username
            comment["time_ago"] = time_ago(comment["created_at"])
        # Get the total number of posts to calculate total pages
        total_comments = query_db(
            "SELECT COUNT(*) as count FROM Comments where post_id = ?", [post_id], one=True
        )["count"]

        user_posted_id = query_db(
            "select user_id from Posts where post_id = ?", args=[post_id], one=True
        )["user_id"]

        username_posted = query_db(
            "select username from Users where user_id = ?", args=[user_posted_id], one=True
        )["username"]

        tag_ids = query_db("select tag_id from PostTags where post_id = ?", args=[post_id])
        tags = []
        for id in tag_ids:
            tags.append(
                query_db(
                    "select tag_name from Tags where tag_id = ?",
                    args=[id["tag_id"]],
                    one=True,
                )["tag_name"]
            )

        upvote_count = query_db(
            "select COUNT(*) as upvote_count from Votes where post_id = ? and vote_type = ?",
            [post_id, "upvote"],
            one=True,
        )["upvote_count"]

        post["time_ago"] = time_ago(post["created_at"])

        total_pages = (total_comments + per_page - 1) // per_page  # Total pages
    except Exception as e:
        print(e)
        return "Internal server error",500

    try:
        sql_query = """UPDATE Posts
         SET views = views + 1
         WHERE post_id = ?
         """
        updating = query_db(sql_query, [post_id])
        views = query_db(
            "select views from Posts where post_id = ? ", [post_id], one=True
        )["views"]
        return render_template(
            f"{language}/post.html",
            post=post,
            username=username_posted,
            tags=tags,
            upvote_count=upvote_count,
            comments=comments,
            is_logged=check_is_logged(),
            views=views,
        )
    except Exception as e:
        print(f"Error rendering template: {e}")
        return "Internal server error", 500


@app.route("/questions/ask")
def ask_question():
    return render_template(f"{language}/ask_question.html")


@app.route("/save_post", methods=["POST"])
def save_post():
    post_data = request.json
    title = post_data["title"]
    body = post_data["body"]
    tags = post_data["tags"]
    username = session["username"]

    user_id = query_db(
        "SELECT user_id FROM Users WHERE username = ?", [username], one=True
    )["user_id"]

    db = get_db()
    cursor = db.cursor()
    try:
        # Insert the post
        cursor.execute(
            "INSERT INTO Posts (user_id, title, body) VALUES (?, ?, ?);",
            (user_id, title, body),
        )
        db.commit()

        # Get the post_id of the newly inserted post
        post_id = query_db("SELECT MAX(post_id) as new_post_id FROM Posts", one=True)[
            "new_post_id"
        ]

        # Insert tags
        for tag in tags:
            tag_id = query_db(
                "SELECT tag_id FROM Tags WHERE tag_name = ?", [tag], one=True
            )["tag_id"]
            cursor.execute(
                "INSERT INTO PostTags (post_id, tag_id) VALUES (?, ?);",
                (post_id, tag_id),
            )

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
    page = request.args.get("page", 1, type=int)
    per_page = 5  # Number of items to show per page

    # Calculate the offset (how many rows to skip)
    offset = (page - 1) * per_page

    # Query the database to get the posts for the current page
    # print(per_page,offset)
    db = get_db()
    cursor = db.cursor()
    posts = cursor.execute(
        "SELECT * FROM Posts ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()

    # Get the total number of posts to calculate total pages
    total_posts = db.execute("SELECT COUNT(*) as count FROM Posts").fetchone()["count"]
    total_pages = (total_posts + per_page - 1) // per_page  # Total pages

    for post in posts:
        post["time_ago"] = time_ago(post["created_at"])
    # Render the template and pass the posts, current page, and total pages
    return render_template(
        f"{language}/questions.html", posts=posts, page=page, total_pages=total_pages
    )


@app.route("/myquestions")
def myquestions():
    username = session["username"]

    user_id = query_db(
        "SELECT user_id FROM Users WHERE username = ?", [username], one=True
    )["user_id"]

    my_posts = query_db("SELECT * from Posts WHERE user_id = ?", args=[user_id])

    return render_template(f"{language}/myquestions.html", posts=my_posts)


@app.route("/upvote", methods=["POST"])
def upvote():
    data = request.json

    username = session["username"]
    post_id = data["post_id"]
    vote_type = "upvote"

    user_id = query_db(
        "select user_id from Users where username = ?", [username], one=True
    )["user_id"]
    to_username = data["username"]

    db = get_db()
    cursor = db.cursor()

    print(user_id, post_id, vote_type)

    has_downvoted = query_db(
        "select vote_type from Votes where user_id = ? and vote_type = ? and post_id = ?",
        [user_id, "downvote", post_id],
    )
    print(has_downvoted)
    try:
        if has_downvoted == []:
            pass
        else:
            print("deleting")
            cursor.execute(
                "DELETE FROM Votes WHERE post_id = ? and vote_type = ?",
                [post_id, "downvote"],
            )
            db.commit()

        cursor.execute(
            "INSERT INTO Votes (post_id,user_id,vote_type) VALUES (?,?,?);",
            (post_id, user_id, vote_type),
        )
        db.commit()

        cursor.execute(
            "INSERT INTO notifications (from_username,to_username,kind,post_id) VALUES (?,?,?,?);",
            (username, to_username, "upvote", post_id),
        )
        db.commit()

    except sqlite3.Error as e:
        print(e)
        flash(e)
        return jsonify({"error": e})
    finally:
        db.close()

    return jsonify({"status": "ok"})


@app.route("/downvote", methods=["POST"])
def downvote():
    data = request.json

    username = session["username"]
    post_id = data["post_id"]
    vote_type = "downvote"

    user_id = query_db(
        "select user_id from Users where username = ?", [username], one=True
    )["user_id"]
    db = get_db()
    cursor = db.cursor()

    print(user_id, post_id, vote_type)

    has_upvoted = query_db(
        "select vote_type from Votes where user_id = ? and vote_type = ? and post_id = ?",
        [user_id, "upvote", post_id],
    )
    print(has_upvoted)
    try:
        if has_upvoted == []:
            pass
        else:
            cursor.execute(
                "DELETE FROM Votes WHERE user_id = ? and vote_type = ? and post_id = ?",
                [user_id, "upvote", post_id],
            )
            db.commit()

        cursor.execute(
            "INSERT INTO Votes (post_id,user_id,vote_type) VALUES (?,?,?);",
            (post_id, user_id, vote_type),
        )
        db.commit()

    except sqlite3.Error as e:
        app.logger.error(e)
        flash(e)
        return jsonify({"error": e})
    finally:
        db.close()

    return jsonify({"status": "ok"})


@app.route("/notifications")
def notifications():
    username = session["username"]
    is_logged = check_is_logged()

    notifs = query_db("select * from notifications where to_username = ?", [username])
    notifs = sorted(
        notifs,
        key=lambda x: datetime.strptime(x["created_at"], "%Y-%m-%d %H:%M:%S"),
        reverse=True,
    )

    for nott in notifs:
        nott["time_ago"] = time_ago(nott["created_at"])
    print(notifs)
    return render_template(f"{language}/notifications.html", notifs=notifs, is_logged=is_logged)


@app.route("/search")
def search():
    search_parameter = request.args["search_word"]

    search_result = query_db(
        f"select * from Posts where body like '%{search_parameter}%' or title like '%{search_parameter}%'",
        one=False,
    )

    return render_template(f"{language}/search_result.html", posts=search_result)


@app.route("/yourprofile")
def yourprofile():
    is_logged = False

    if "username" in session:
        username = session["username"]
        email = query_db(
            "select email from Users where username = ?", [username], one=True
        )["email"]
        is_logged = True

    return render_template(
        f"{language}/myprofile.html", username=username, email=email, is_logged=is_logged
    )


@app.route("/profile/update", methods=["POST"])
def profile_update():
    username = request.form["username"]
    email = request.form["email"]
    db = get_db()
    cursor = db.cursor()

    old_username = session["username"]
    print(session["username"], username)
    if session["username"] != username:
        try:
            cursor.execute(
                "UPDATE Users SET username=? WHERE username=? ;",
                (username, old_username),
            )
            db.commit()

        except sqlite3.Error as e:
            print(e)
        session["username"] = username

    old_email = query_db(
        f"select email from Users where username = '{old_username}'  ;", one=True
    )

    print(old_email, email)
    if old_email != email:
        try:
            cursor.execute(
                "UPDATE Users SET email =? WHERE username =?;", (email, old_username)
            )
            db.commit()
        except sqlite3.Error as e:
            print(e)

    return redirect("/yourprofile")


@app.route("/comment-post", methods=["POST"])
def comment_post():
    is_logged = check_is_logged()
    print(is_logged)
    if not is_logged:
        return redirect("/login")
    db = get_db()
    cursor = db.cursor()
    comment_data = request.json
    username = session["username"]
    user_id = query_db(
        "select user_id from Users where username = ?", [username], one=True
    )["user_id"]
    comment_body = comment_data["body"]
    post_id = comment_data["post_id"]
    try:
        print(post_id, user_id, comment_body)
        cursor.execute(
            "INSERT INTO Comments  (post_id,user_id,body) VALUES (?,?,?);",
            (post_id, user_id, comment_body),
        )
        db.commit()
    except sqlite3.Error as e:
        print(e)
    finally:
        db.close()

    return redirect(url_for("posts", post_id=post_id))


@app.route("/delete-comment/<comment_id>")
def delete_comment(comment_id):
    post_id = query_db(
        "select post_id from Comments where comment_id = ?", [comment_id], one=True
    )["post_id"]
    delete = query_db("DELETE FROM Comments WHERE comment_id = ? ", [comment_id])
    print(delete)

    return redirect(url_for("posts", post_id=post_id))


@app.route("/logout")
def logout():
    session.pop("username", "")
    session.pop("email", "")
    return redirect("/home")


@google.tokengetter
def get_google_oauth_token():
    return session.get("google_token")


if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
