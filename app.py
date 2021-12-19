import os
import re
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
#ignore this for windows systems
# if not (os.environ.get("API_KEY")):
#     raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    cash = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])
    cash = cash[0]["cash"]
    values = db.execute("SELECT sum(value), symbol FROM shares WHERE id = ? GROUP BY symbol",session["user_id"])
    print(values)
    prices = []
    total = 0
    for value in values:
        shares = value["sum(value)"]
        symbol = value["symbol"]
        quote = lookup(symbol)
        if shares != 0:
            prices.append({'symbol':quote["symbol"], 'name':quote["name"], 'shares':shares, 'price':usd(quote["price"]), 'total':usd(quote["price"] * shares)})
        total = shares * quote["price"] + total
    total = total + cash
    cash = usd(cash)
    total = usd(total)
    if session['key'] != 0 :
        alert = session['key']
    else:
        alert = 0
    #alert = request.args.get("alert")
    return render_template("index.html", prices = prices,cash = cash, total = total, alert = alert)





@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    elif request.method == "POST":

        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("symbol does not exist")
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("input is not a positive integer")
        quote = lookup(symbol)
        name = quote["name"]
        price = quote["price"]
        symbol = quote["symbol"]
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])
        # user_id symbol of stock bought number of stocks money spent remaining money
        cash = cash[0]["cash"]
        if cash >= (shares * price):

            #db.execute("UPDATE users SET cash = :cash WHERE id = :id",cash = cash - (shares * price), id = session["user_id"])
            db.execute("INSERT INTO buy (id, symbol, price, shares, total) VALUES (?,?,?,?,?)", session["user_id"], quote["symbol"], quote["price"], shares, shares * price )
            db.execute("INSERT INTO shares (id, shares, symbol, cash, value) VALUES (?,?,?,?,?)", session["user_id"], shares, quote["symbol"], cash - (shares * price), 1 * shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?",cash - (shares * price), session["user_id"])
            alert = "Bought!"
            session['key'] = alert
            return redirect("/")
        else:
            return  apology("not enough cash", 403)



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    values = db.execute("SELECT value, symbol, timestamp FROM shares WHERE id = ? ",session["user_id"])
    print(values)
    i = 0
    prices = []
    total = 0
    for value in values:
        shares = value["value"]
        symbol = value["symbol"]
        timestamp = value["timestamp"]
        quote = lookup(symbol)
        prices.append({'symbol':quote["symbol"],'timestamp':timestamp, 'shares':shares, 'price':quote["price"]})

    print(prices)

    return render_template("history.html", prices = prices)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["key"] = 0

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("symbol must go back", 403)
        quote = lookup(symbol)
        price = usd(quote["price"])
        return render_template("quoted.html",quote=quote,price = price)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 403)
        if username in db.execute("SELECT username FROM users"):
            return apology("username already exists", 403)

        password = request.form.get("password")
        if not password:
            return apology("must provide password", 403)
        def password_check(password):

        #Verify the strength of 'password'
        #Returns a dict indicating the wrong criteria
        #A password is considered strong if:
        #8 characters length or more
        #1 digit or more
        #1 symbol or more
        #1 uppercase letter or more
        #1 lowercase letter or more

            # calculating the length
            length_error = len(password) < 8 or len(password) > 12

            # searching for digits
            digit_error = re.search(r"\d", password) is None

            # searching for uppercase
            uppercase_error = re.search(r"[A-Z]", password) is None

            # searching for lowercase
            lowercase_error = re.search(r"[a-z]", password) is None

            # searching for symbols
            symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

            # overall result
            password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

            return {
                # 'password_ok' : password_ok,
                'password_ok' : 1,
                'length_error' : length_error,
                'digit_error' : digit_error,
                'uppercase_error' : uppercase_error,
                'lowercase_error' : lowercase_error,
                'symbol_error' : symbol_error,
                }
        check = password_check(password)
        if check['password_ok'] == 1:
            confirmation = request.form.get("confirmation")
            if confirmation != password:
                return apology("passwords donot match", 403)
            hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)",request.form.get("username"),generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            return redirect("/")
        else:
            return apology("password constraint didnt match",403)

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        row = db.execute("SELECT DISTINCT symbol FROM shares WHERE id = ?",session["user_id"])
        print(row)
        return render_template("sell.html",row=row)
    elif request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        quote = lookup(symbol)
        name = quote["name"]
        price = quote["price"]
        symbol = quote["symbol"]
        value = db.execute("SELECT sum(value) FROM shares WHERE id = ? AND symbol = ?",session["user_id"], symbol)
        if shares <= value[0]['sum(value)']:
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])
            cash = cash[0]["cash"]
            db.execute("INSERT INTO sell (id, symbol, price, shares, total) VALUES (?,?,?,?,?)", session["user_id"], quote["symbol"], quote["price"], shares, shares * price )
            db.execute("INSERT INTO shares (id, shares, symbol, cash, value) VALUES (?,?,?,?,?)", session["user_id"], shares, quote["symbol"], cash + (shares * price), (-1) * shares)
            db.execute("UPDATE users SET cash = ? WHERE id = ?",cash + (shares * price), session["user_id"])
            alert = "Sold!"
            session['key'] = alert
            return redirect("/")
        else:
            return apology("not enough shares",403)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "GET":
        return render_template("add.html")
    else:
        cash = int(request.form.get("cash"))
        rows = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])
        cash = cash + rows[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
        alert = "Added!"
        session['key'] = alert
        return redirect("/")

@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "GET":
        return render_template("change.html")
    else:
        rows = db.execute("SELECT * FROM users WHERE id = ?",session["user_id"])
        if check_password_hash(rows[0]["hash"], request.form.get("password")):
            new = request.form.get("newpassword")
            if check_password_hash(rows[0]["hash"], new):
                return apology("this is same as the previos password")

            else:
                hash = generate_password_hash(new, method='pbkdf2:sha256', salt_length=8)
                db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new, method='pbkdf2:sha256', salt_length=8), session["user_id"])
                alert = "Changed!"
                session['key'] = alert
                return redirect("/")


        else:
            apology("enter correct password",403)

    return apology("todo",403)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
