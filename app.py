import os
import pathlib
import requests
import psycopg2.extras
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort
import psycopg2
import psycopg2.extras
import re
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
 
app = Flask(__name__)
app.secret_key = 'cairocoders-ednalan'
DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "erhan.2001"

conn = psycopg2.connect(host=DB_HOST,dbname=DB_NAME, user=DB_USER, password=DB_PASS)

#Google Connection
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev
GOOGLE_CLIENT_ID = "733339164445-d0o2qd6f28dpkv792ckt80adv3cmn47e.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=10

    )

    session["google_id"] = id_info.get("sub")
    session["username"] = id_info.get("name")
    session['loggedin'] = True
    return redirect(url_for('home'))
@app.route("/glogin")
def glogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

###login and register
@app.route('/')

def home():

    # Check if user is loggedin
    if 'loggedin' in session:

        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'])
    # User is not loggedin redirect to login page

    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        print(password)

        query = f"SELECT * FROM users WHERE email = '{email}'"
        # Check if account exists using MySQL
        cursor.execute(query)
        # Fetch one record and return result
        account = cursor.fetchone()
        print(account)

        if account:
            id = account[0]
            username = account[1]
            email = account[3]
            password_rs = account[2]
            # If account exists in users table in out database
            if check_password_hash(password_rs, password):
                # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = id
                session['email'] = email
                session['username'] = username
                # Redirect to home page
                return redirect(url_for('home'))
            else:
                # Account doesnt exist or username/password incorrect
                print("Hata")
                flash('Incorrect username/password')
        else:
            # Account doesnt exist or username/password incorrect
            flash('Incorrect username/password')

    return render_template('loginsignform.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        _hashed_password = generate_password_hash(password)

        #Check if account exists using MySQL
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        account = cursor.fetchone()
        print(account)
        # If account exists show error and validation checks
        if account:
            flash('Account already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash('Username must contain only characters and numbers!')
        elif not username or not password or not email:
            flash('Please fill out the form!')
        else:
            # Account doesnt exists and the form data is valid, now insert new account into users table
            cursor.execute("INSERT INTO users (username, password, email) VALUES (%s,%s,%s)", (username, _hashed_password, email))
            conn.commit()
            flash('You have successfully registered!')
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        flash('Please fill out the form!')
    # Show registration form with message (if any)
    return render_template('loginsignform.html')

@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

@app.route('/profile')
def profile():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if user is loggedin
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
    #
