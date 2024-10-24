import os
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from login import apology, login_required

app = Flask(__name__)

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Database connection function
def get_db_connection():
    """Connect to the SQLite database."""
    conn = sqlite3.connect('project.db')
    conn.row_factory = sqlite3.Row  # This allows us to access rows as dictionaries
    return conn

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
    """Display workout logs."""
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM workouts WHERE user_id = ? ORDER BY time DESC", (session["user_id"],)).fetchall()
    conn.close()

    if len(logs) < 1:
        return render_template("create.html")
    return render_template("index.html", logs=logs)

@app.route("/routine", methods=["GET", "POST"])
@login_required
def routine():
    """Handle workout routine creation."""
    if request.method == "POST":
        name = request.form.get("name").upper()
        weight = request.form.get("weight")
        sets = request.form.get("sets")
        reps = request.form.get("reps")

        # Validation of input data
        if not name:
            return apology("name needed", 403)
        elif not sets or not sets.isdigit() or int(sets) <= 0:
            return apology("cant count negative on sets", 403)
        elif not reps or not reps.isdigit() or int(reps) <= 0:
            return apology("cant count negative on reps", 403)
        elif not weight or not weight.isdigit() or int(weight) <= 0:
            return apology("cant do negative weight", 403)

        # Insert the workout data into the database
        conn = get_db_connection()
        conn.execute("INSERT INTO workouts (user_id, name, weight, sets, reps) VALUES (?, ?, ?, ?, ?)",
                     (session["user_id"], name, weight, sets, reps))
        conn.commit()
        conn.close()

        # Flash success message and redirect
        flash(f"Well done on {name} with {weight}Kg for {sets} sets and {reps} reps!")
        return redirect("/")
    else:
        return render_template("routine.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        conn = get_db_connection()
        lines = conn.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),)).fetchall()
        conn.close()

        # Ensure username exists and password is correct
        if len(lines) != 1 or not check_password_hash(lines[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = lines[0]["id"]

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user."""
    # Forget any user_id
    session.clear()

    if request.method == "POST":
        """ask the username, password, and confirmation"""
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must type a username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must type a password", 403)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm your password", 403)

        # Ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must type the same password", 403)

        # Query database for username
        conn = get_db_connection()
        rows = conn.execute("SELECT id FROM users WHERE username = ?", (request.form.get("username"),)).fetchall()

        # Check if username already exists
        if len(rows) != 0:
            conn.close()
            return apology("username already exists", 403)

        # Insert the new user into the database
        conn.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                     (request.form.get("username"), generate_password_hash(request.form.get("password"))))
        conn.commit()

        # Remember which user has registered
        lines = conn.execute("SELECT id FROM users WHERE username = ?", (request.form.get("username"),)).fetchall()
        session["user_id"] = lines[0]["id"]
        conn.close()

        # Redirect user to login page
        return redirect("/login")
    else:
        return render_template("register.html")

@app.route("/logout")
def logout():
    """Log user out."""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/analisis", methods=["GET", "POST"])
@login_required
def analisis():
    """Analyze the user's workout progress."""
    conn = get_db_connection()
    logs = conn.execute("SELECT name FROM workouts WHERE user_id = ? ORDER BY weight DESC", (session["user_id"],)).fetchall()

    if request.method == "POST":
        match = request.form.get("match").upper()

        # Ensure the user provided a match (exercise name)
        if not match:
            conn.close()
            return apology("need the name of the exercise", 403)

        # Query for the most recent and best personal record workout
        on = conn.execute("SELECT * FROM workouts WHERE name = ? AND user_id = ? ORDER BY time DESC LIMIT 1",
                          (match, session["user_id"])).fetchall()

        pa = conn.execute("""SELECT CASE WHEN reps > 1 THEN reps END AS reps, weight 
                             FROM workouts WHERE name = ? AND user_id = ? ORDER BY weight DESC LIMIT 1""",
                          (match, session["user_id"])).fetchall()

        # Calculate the personal record (PR)
        if len(pa) != 0 and pa[0]["reps"] is not None:
            pr = pa[0]["weight"] + (pa[0]["reps"] - 1) * 5
        else:
            conn.close()
            return render_template("analisis.html", on=on)

        # Query for the current and previous workout details
        current = conn.execute("SELECT weight, reps FROM workouts WHERE name = ? AND user_id = ? ORDER BY time DESC LIMIT 1",
                               (match, session["user_id"])).fetchall()

        previus = conn.execute("SELECT weight, reps FROM workouts WHERE name = ? AND user_id = ? ORDER BY time ASC LIMIT 1",
                               (match, session["user_id"])).fetchall()

        conn.close()

        # Initialize variables for the progress comparison
        more = None
        less = None
        rep_more = None
        rep_less = None

        # Compare current weight and reps with previous workout
        if current[0]["weight"] >= previus[0]["weight"]:
            more = current[0]["weight"] - previus[0]["weight"]
        else:
            less = previus[0]["weight"] - current[0]["weight"]

        if current[0]["reps"] >= previus[0]["reps"]:
            rep_more = current[0]["reps"] - previus[0]["reps"]
        else:
            rep_less = previus[0]["reps"] - current[0]["reps"]

        return render_template("analisis.html", on=on, pr=pr, more=more, less=less, rep_more=rep_more, rep_less=rep_less)
    else:
        conn.close()
        return render_template("analisis.html", logs=logs)
