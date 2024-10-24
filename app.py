import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from login import apology, login_required

app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///project.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    logs = db.execute("SELECT * FROM workouts WHERE user_id = :user_id ORDER BY time DESC""", user_id=session["user_id"])

    if len(logs) < 1:
        return render_template("create.html")





    return render_template("index.html", logs = logs)


@app.route("/routine", methods=["GET", "POST"])
@login_required
def routine():
    if request.method == "POST":
        name = request.form.get("name").upper()
        weight = request.form.get("weight")
        sets= request.form.get("sets")
        reps = request.form.get("reps")

        if not name:
            return apology("name needed",403)
        elif not sets or not sets.isdigit() or int(sets) <= 0:
            return apology("cant count negative on sets", 403)
        elif not reps or not reps.isdigit() or int(reps) <= 0:
            return apology("cant count negative on reps", 403)
        elif not weight or not weight.isdigit() or int(weight) <= 0:
            return apology("cant do negative weight", 403)


        db.execute("INSERT INTO workouts (user_id, name, weight, sets, reps) VALUES (:user_id, :name, :weight, :sets, :reps)", user_id=session["user_id"], name=name, weight= weight, sets=sets, reps=reps)

        flash(f"Well done on {name} with {weight}Kg for {sets}sets and {reps}reps!")

        return redirect("/")
    else:
        return render_template("routine.html")









@app.route("/login", methods=["GET", "POST"])
def login():



    session.clear()


    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        lines = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(lines) != 1 or not check_password_hash(lines[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = lines[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    if request.method == "POST":
        """ask the username, password, and confirmation"""
        if not request.form.get("username"):
            return apology("must type a usernam", 403)
        elif not request.form.get("password"):
            return apology("must type a password", 403)
        elif not request.form.get("confirmation"):
            return apology("must confirm your password", 403)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must type the same password", 403)

        rows = db.execute("SELECT id FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exists", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), generate_password_hash(request.form.get("password")))

        lines = db.execute("SELECT id FROM users WHERE username = ?", request.form.get("username"))

        session["user_id"] = lines[0]["id"]

        return redirect("/login")
    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/analisis", methods=["GET", "POST"])
def analisis():

    logs = db.execute("SELECT name FROM workouts WHERE user_id = :user_id ORDER BY weight DESC""", user_id=session["user_id"])

    if request.method == "POST":
        match = request.form.get("match").upper()
        guess = request.form.get("guess")
        if not match:
            return apology("need the name of the exercise",403)
        for log in logs:
            on = db.execute("SELECT * FROM workouts WHERE name = :match AND user_id = :user_id ORDER BY time DESC limit 1", match=match, user_id=session["user_id"])
        pa = db.execute("""SELECT CASE WHEN reps > 1 THEN reps END AS reps, weight FROM workouts WHERE name = :match AND user_id = :user_id ORDER BY weight DESC LIMIT 1""", match=match, user_id=session["user_id"])
        if len(pa) != 0 and pa[0]["reps"] is not None:
            pr = pa[0]["weight"] + (pa[0]["reps"] - 1) * 5
        else:
            return render_template("analisis.html", on=on)

        current = db.execute("SELECT weight, reps FROM workouts WHERE name = :match AND user_id = :user_id ORDER BY time DESC limit 1", match=match, user_id=session["user_id"])
        previus = db.execute("SELECT weight, reps FROM workouts WHERE name = :match AND user_id = :user_id ORDER BY time ASC limit 1", match=match, user_id=session["user_id"])

        more = None
        less = None
        rep_more = None
        rep_less = None

        if current[0]["weight"] >= previus[0]["weight"]:
            more = current[0]["weight"] - previus[0]["weight"]
        else:
            less = previus[0]["weight"] - current[0]["weight"]


        if current[0]["reps"] >= previus[0]["reps"]:
            rep_more = current[0]["reps"] - previus[0]["reps"]
        else:
            rep_less = previus[0]["reps"] - current[0]["reps"]

        return render_template("analisis.html", on=on, pr=pr, more=more, less=less, rep_more=rep_more, rep_less=rep_less )


    else:
        return render_template("analisis.html", logs=logs)


