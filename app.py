import os
import pathlib
import mode
import requests
import datetime
import random
import psycopg2.extras
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort, jsonify, send_file, json
import psycopg2
import psycopg2.extras
import re
from datetime import datetime
from oauthlib.uri_validate import query
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import random
import uuid
from werkzeug.utils import secure_filename



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
    session["id"] = id_info.get("sub")
    session["username"] = id_info.get("name")
    session["email"] = id_info.get("email")
    session['loggedin'] = True
    session['folder_id'] = 0
    email = session["email"]
    username = session["username"]
    id = session["id"]
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    query = f"SELECT* FROM users WHERE id = '{id}'"
    cursor.execute(query)
    user_find=cursor.fetchall()
    print(id)
    if not user_find:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("INSERT INTO users (id,username, email) VALUES (%s,%s,%s)", (str(id), username, email))
        conn.commit()

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
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        #conn.session.rollback()
        query = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = 0 "
        cursor.execute(query)

        folders = cursor.fetchall()
        session['folder_id'] = 0
        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'], folders=folders)
    # User is not loggedin redirect to login page

    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    session['folder_id'] = 0
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
            email = account[1]
            password_rs = account[2]
            username = account[5]

            if check_password_hash(password_rs, password):
                # Account doesnt exist or username/password incorrect
                print("başarılı")
                flash('Incorrect username/password')
                session['loggedin'] = True
                session['id'] = id
                session['email'] = email
                session['username'] = username
                return redirect(url_for('home'))
            else:
                # Account doesnt exist or username/password incorrect
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
        my_uuid = uuid.uuid4()
        #Check if account exists using MySQL
        query = f"SELECT * FROM users WHERE username = '{username}'"

        cursor.execute(query)
        account = cursor.fetchone()


        print('Your UUID is: ' + str(my_uuid))
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
            cursor.execute("INSERT INTO users (id,username, password, email) VALUES (%s,%s,%s,%s)", (str(my_uuid),username,_hashed_password, email))
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
@app.route('/folders/<folder_id>')
def folders(folder_id):
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        session['folder_id'] = folder_id

        print(folder_id)
        query = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = '{folder_id}' "

        cursor.execute(query)
        folders = cursor.fetchall()

        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'], folders=folders)
    # User is not loggedin redirect to login page

    return redirect(url_for('login'))

@app.route('/create_folder', methods=['POST'])
def create_folder():

    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    name = request.form.get('folder_name')
    user_id = session.get('id')
    folder_id = session.get('folder_id')
    print(folder_id)
    print(name)
    print(user_id)
    #conn.session.rollback()

    if user_id:
        print("test")
        query = """ INSERT INTO folders (name, user_id, parent) VALUES (%s, %s, %s) """
        values = (name, str(user_id), folder_id)
        cursor.execute(query, values)
        conn.commit()

    return redirect(url_for('folders', folder_id=folder_id))
@app.route('/thrash/<folder_id>')
def thrash(folder_id):
    #   # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        print(folder_id)
        query = f"INSERT INTO thrash (thrash_user_id,thrash_folder_id, folders_created_time,thrash_folder_name) SELECT user_id, id, data_created,name FROM folders WHERE  user_id = '{user_id}' AND id = '{folder_id}'"
        cursor.execute(query)
        sqlquery = f"DELETE FROM folders WHERE  user_id = '{user_id}' AND id = '{folder_id}' OR parent ='{folder_id}'"
        cursor.execute(sqlquery)
        conn.commit()
        # User is loggedin show them the home page
        return redirect(url_for('home'))
     #User is not loggedin redirect to login page
    return redirect(url_for('login'))
@app.route('/thrashs/')
def thrashs():
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        print(user_id)
        query = f"SELECT * FROM thrash WHERE thrash_user_id= '{user_id}' "
        cursor.execute(query)
        folders = cursor.fetchall()

        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'], folders=folders)
    # User is not loggedin redirect to login page

    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_files():
    info = {'success': False, 'errors': []}

    if request.method == 'POST' and 'data_type' in request.form and request.form['data_type'] == 'upload_files':
        folder = 'uploads/'
        if not os.path.exists(folder):
            os.makedirs(folder, 0o777, True)
            with open(os.path.join(folder, ".HTACCESS"), "w") as htaccess_file:
                htaccess_file.write("Options -Indexes")

        for key, file in request.files.items():
            destination = os.path.join(folder, str(int(datetime.datetime.now().timestamp())) + file.filename)
            if os.path.exists(destination):
                destination = os.path.join(folder, str(int(datetime.datetime.now().timestamp())) + str(random.randint(0, 9999)) + file.filename)

            file.save(destination)

            # Check if there is enough space to save the file
            occupied = info.get('drive_occupied', 0)
            drive_total = info.get('drive_total', 0) * (1024 * 1024 * 1024)

            if occupied + os.path.getsize(destination) <= drive_total:
                # Save to database
                file_type = file.content_type
                date_created = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                date_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file_name = file.filename
                file_path = destination
                file_size = os.path.getsize(destination)
                user_id = getattr(request.session.get('MY_DRIVE_USER', {}), 'id', 0)
                folder_id = int(request.form.get('folder_id', 0))
                slug = generate_slug()

                query_string = f"INSERT INTO mydrive (file_name, file_size, file_path, user_id, file_type, date_created, date_updated, folder_id, slug) VALUES " \
                               f"('{file_name}', '{file_size}', '{file_path}', '{user_id}', '{file_type}', '{date_created}', '{date_updated}', '{folder_id}', '{slug}')"

                query(query_string)

                info['success'] = True
            else:
                info['success'] = False
                info['errors'].append("You don't have enough space to add that file")

    return info


@app.route('/process_data', methods=['POST'])
def process_data():
    info = {}
    info['success'] = False
    info['LOGGED_IN'] = is_logged_in()
    info['data_type'] = request.form.get('data_type', '')

    works_without_login = ['user_signup', 'user_login', 'preview_file']
    if not info['LOGGED_IN'] and info['data_type'] not in works_without_login:
        return jsonify(info)

    info['username'] = session.get('MY_DRIVE_USER', {}).get('username', 'User')
    info['drive_occupied'] = get_drive_space(session.get('MY_DRIVE_USER', {}).get('id', 0))
    info['drive_total'] = 10  # in GBs
    info['breadcrumbs'] = []

    return jsonify(info)

if __name__ == "__main__":
    app.run(debug=True)
    #
