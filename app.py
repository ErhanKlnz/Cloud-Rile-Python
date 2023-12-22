import os
import pathlib
import requests
import datetime
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
from flask import Flask, url_for, request, send_from_directory, send_file
# from authlib.integrations.flask_client import OAuth, OAuthError
from dotenv import load_dotenv
from flask import Flask, redirect, url_for, session
from flask_oauthlib.client import OAuth
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'static\\uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv'}
MAX_USER_ALLOCATION = 5000000  # in bytes

app = Flask(__name__)
app.debug = True
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000  # max 16 MB
app.secret_key = 'cairocoders-ednalan'
DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "erhan.2001"

conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
# twitter
oauth = OAuth(app)

facebook = oauth.remote_app(
    'facebook',
    consumer_key='658072539821648',
    consumer_secret='9de56776348dc352ff38bd2e82bea2a3',
    request_token_params={'scope': 'email'},
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth'
)


@app.route('/f_login')
def f_login():
    return facebook.authorize(callback=url_for('authorized', _external=True))


@app.route('/login/authorized')
def authorized():
    response = facebook.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Giriş yapılamadı!'
    session['facebook_token'] = (response['access_token'], '')
    return 'Başarıyla giriş yapıldı!'


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('facebook_token')


# Google Connection
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # to allow Http traffic for local dev
GOOGLE_CLIENT_ID = "733339164445-d0o2qd6f28dpkv792ckt80adv3cmn47e.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
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
    user_find = cursor.fetchall()
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
        # conn.session.rollback()
        query_folders = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = 0"
        query_files = f"SELECT * FROM mycloud WHERE user_id='{user_id}' AND folder_id = 0"
        query_current_space = f"SELECT SUM(file_size) FROM mycloud WHERE user_id='{user_id}'"

        cursor.execute(query_current_space)
        current_space = cursor.fetchall()
        if current_space[0][0] is not None:
            print(current_space)
            current_space = current_space[0][0]
            current_space_as_percent = int((current_space / MAX_USER_ALLOCATION) * 100)
        else:
            current_space = 0
            current_space_as_percent = 0
        cursor.execute(query_folders)
        folders = cursor.fetchall()

        cursor.execute(query_files)
        files = cursor.fetchall()

        session['folder_id'] = 0
        for i in folders:
            q_folder = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = '{i[0]}'"
            q_file = query_files = f"SELECT * FROM mycloud WHERE user_id='{user_id}' AND folder_id = {i[0]}"
            cursor.execute(q_folder)
            f_folder = cursor.fetchall()
            cursor.execute(q_file)
            f_file = cursor.fetchall()
            if len(q_folder) > 0 or len(q_file) > 0:
                i.insert(len(i), True)
            else:
                i.insert(len(i), False)
        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'], folders=folders, files=files,
                               folder_id=0, current_space_as_percent=current_space_as_percent,
                               current_space=current_space, max_space=MAX_USER_ALLOCATION)
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
    if request.method == 'POST' and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access

        password = request.form['password']
        email = request.form['email']
        _hashed_password = generate_password_hash(password)
        my_uuid = uuid.uuid4()
        username = email.split('@')[0]
        print(username)
        # Check if account exists using MySQL
        query = f"SELECT * FROM users WHERE email='{email}'"

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
            cursor.execute("INSERT INTO users (id,username, password, email) VALUES (%s,%s,%s,%s)",
                           (str(my_uuid), username, _hashed_password, email))
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

        query = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = '{folder_id}' "
        query_files = f"SELECT * FROM mycloud WHERE user_id='{user_id}' AND folder_id = {folder_id}"
        query_current_space = f"SELECT SUM(file_size) FROM mycloud WHERE user_id='{user_id}'"

        cursor.execute(query_current_space)
        current_space = cursor.fetchall()
        if current_space[0][0] is not None:
            print(current_space)
            current_space = current_space[0][0]
            current_space_as_percent = int((current_space / MAX_USER_ALLOCATION) * 100)
        else:
            current_space = 0
            current_space_as_percent = 0

        cursor.execute(query)
        folders = cursor.fetchall()
        cursor.execute(query_files)
        files = cursor.fetchall()
        for i in folders:
            q_folder = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = '{i[0]}'"
            q_file = query_files = f"SELECT * FROM mycloud WHERE user_id='{user_id}' AND folder_id = {i[0]}"
            cursor.execute(q_folder)
            f_folder = cursor.fetchall()
            cursor.execute(q_file)
            f_file = cursor.fetchall()
            if len(f_folder) > 0 or len(f_file) > 0:
                i.insert(len(i), True)
            else:
                i.insert(len(i), False)

        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'], folders=folders, files=files,
                               folder_id=folder_id, current_space_as_percent=current_space_as_percent,
                               current_space=current_space, max_space=MAX_USER_ALLOCATION)
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
    # conn.session.rollback()

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
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/thrashs/')
def thrashs():
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        query = f"SELECT * FROM thrash WHERE thrash_user_id= '{user_id}' "
        cursor.execute(query)
        folders = cursor.fetchall()
        for i in folders:
            q = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = '{i[0]}'"
            cursor.execute(q)
            a = cursor.fetchall()
            if len(a) > 0:
                i.insert(len(i), True)
            else:
                i.insert(len(i), False)

        # User is loggedin show them the home page
        return render_template('inside_page.html', username=session['username'], folders=folders, folder_id=0)
    # User is not loggedin redirect to login page

    return redirect(url_for('login'))


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload/to/<folder_id>', methods=['GET', 'POST'])
def upload_file(folder_id):
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        user_id = session["id"]

        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        query_current_space = f"SELECT SUM(file_size) FROM mycloud WHERE user_id='{user_id}'"
        cursor.execute(query_current_space)
        current_space = cursor.fetchall()[0][0]
        if current_space is None:
            current_space = 0
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            folder = os.path.join(app.config['UPLOAD_FOLDER'], user_id, folder_id)
            destination = os.path.join(basedir, folder, filename)
            os.makedirs(folder, exist_ok=True)  # Creates the directory,

            file.save(destination)
            file_size = os.path.getsize(destination)
            file_type = file.content_type
            date_created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            date_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not current_space + file_size < MAX_USER_ALLOCATION:
                flash('No space')
                return redirect(request.url)

            query_string = f"INSERT INTO mycloud (file_name, file_size, file_path, user_id, file_type, data_created, data_updated, folder_id, favorite) VALUES " \
                           f"('{filename}', '{file_size}', '{destination}', '{user_id}', '{file_type}', '{date_created}', '{date_updated}', '{folder_id}', 0)"
            cursor.execute(query_string)
            conn.commit()

            return redirect(url_for('home'))
    return redirect(url_for('home'))


@app.route('/download/<folder_id>/<file_name>', methods=['GET', 'POST'])
def download_file(folder_id, file_name):
    folder = os.path.join(app.config['UPLOAD_FOLDER'], session['id'], folder_id)
    destination = os.path.join(basedir, folder)
    return send_from_directory(destination, file_name)


@app.route('/forget_password')
def forget_password():
    if not 'loggedin' in session:
        return render_template('forgetpassword.html')


if __name__ == "__main__":
    load_dotenv()
    app.run(debug=True)
    #
