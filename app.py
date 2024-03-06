import os
import pathlib
import requests
import datetime
import psycopg2.extras
from flask import Flask, request, session, redirect, url_for, render_template, flash, abort, jsonify, send_file, json,send_from_directory,make_response
import psycopg2
import psycopg2.extras
import re
from datetime import datetime, timedelta
from oauthlib.uri_validate import query
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import uuid
# from authlib.integrations.flask_client import OAuth, OAuthError
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from os import getenv
from authlib.integrations.flask_client import OAuth
import secrets
from flask_mail import Mail, Message


UPLOAD_FOLDER = 'static\\uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv','mp4','mp3','AVI','mkv','flv','rar'}
MAX_USER_ALLOCATION = 10000000  # in bytes

app = Flask(__name__)

app.debug = True
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000  # max 16 MB
app.secret_key = 'cairocoders-ednalan'
DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "1234"

conn = psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASS)
# github
oauth = OAuth(app)

github = oauth.register(
    name='github',
    client_id='43eaaad483fb12e6d6c4',
    client_secret='dcbe9ef7393f5144c41a2b07e78f494fce9f28cb',
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
    clock_skew_in_seconds=10
)


@app.route('/github/login')
def githublogin():
    github = oauth.create_client('github')
    redirect_uri = url_for('authorize', _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user', token=token)

    user_info = resp.json()
    github_id = user_info['id']
    username = user_info['login']
    email = user_info['email']
    print(username)
    print(github_id)
    session["id"] = github_id
    session["username"] = username
    session["email"] = email
    session['loggedin'] = True
    session['folder_id'] = 0
    profile = resp.json()
    session['loggedin'] = True
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    query = f"SELECT* FROM users WHERE id = '{id}'"
    cursor.execute(query)
    user_find = cursor.fetchall()

    if not user_find:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("INSERT INTO users (id,username, email) VALUES (%s,%s,%s)", (str(id), username, email))
        conn.commit()

    print(profile, token)
    return redirect(url_for('home'))

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

        cursor.execute(query)

        account = cursor.fetchone()
        print(account)
        if account:
            id = account[0]
            email = account[1]
            password_rs = account[2]
            username = account[5]

            if password_rs is not None and check_password_hash(password_rs, password):
                # Account exists and password matches
                print("başarılı")
                session['loggedin'] = True
                session['id'] = id
                session['email'] = email
                session['username'] = username
                return redirect(url_for('home'))
            else:
                # Password is incorrect
                flash('Hatalı parola')
        else:
            # Account doesn't exist
            flash('Mail adresi bulunamadı. Lütfen kontrol ediniz.')


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
            flash('You have successfully registered!',)
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


@app.route('/thrashs/<folder_id>')
def move_trash(folder_id):
    #   # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        print("Silinen klasörün ID: " + folder_id)
        query = f"INSERT INTO thrash (thrash_user_id,thrash_folder_id, folders_created_time,thrash_folder_name) SELECT user_id, id, data_created,name FROM folders WHERE  user_id = '{user_id}' AND id = '{folder_id}'"
        cursor.execute(query)
        sqlquery = f"DELETE FROM folders WHERE  user_id = '{user_id}' AND id = '{folder_id}' OR parent ='{folder_id}'"
        cursor.execute(sqlquery)
        conn.commit()
        # User is loggedin show them the home page
        return redirect(url_for('home'))
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/thrashs/files/<file_id>')
def delete_file(file_id):
    #   # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        print("Silinen dosyanın ID: " + file_id)
        query = (f"INSERT INTO thrash (thrash_user_id, thrash_folder_id, folders_created_time, thrash_folder_name) "
                 f"SELECT user_id, id, data_created, file_name FROM mycloud "
                 f"WHERE  user_id = '{user_id}' AND id = '{file_id}'")
        cursor.execute(query)
        sqlquery = f"DELETE FROM mycloud WHERE  user_id = '{user_id}' AND id = '{file_id}'"
        cursor.execute(sqlquery)
        conn.commit()
        # User is loggedin show them the home page
        return redirect(url_for('home'))
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/thrashs/remove/<thrash_folder_id>')
def delete_folder(thrash_folder_id):
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        print("Kalıcı silinen klasörün ID: " + thrash_folder_id)
        query = f"DELETE FROM thrash WHERE thrash_user_id = '{user_id}' AND (thrash_folder_id = '{thrash_folder_id}')"
        cursor.execute(query)
        conn.commit()
        # User is loggedin show them the home page
        return redirect(url_for('home'))
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/thrashs/remove/file/<file_id>')
def remove_file(file_id):
    # Check if user is loggedin
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        user_id = session.get('id')
        print("Kalıcı silinen klasörün ID: " + file_id)
        query = f"DELETE FROM thrash WHERE thrash_user_id = '{user_id}' AND (thrash_folder_id = '{file_id}')"
        cursor.execute(query)
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
        query_current_space = f"SELECT SUM(file_size) FROM mycloud WHERE user_id='{user_id}'"

        cursor.execute(query_current_space)
        current_space = cursor.fetchall()
        if current_space[0][0] is not None:
            # print(current_space)
            current_space = current_space[0][0]
            current_space_as_percent = int((current_space / MAX_USER_ALLOCATION) * 100)
        else:
            current_space = 0
            current_space_as_percent = 0
            cursor.execute(query)
        for i in folders:
            q = f"SELECT * FROM folders WHERE user_id= '{user_id}' AND parent = '{i[0]}'"
            cursor.execute(q)
            a = cursor.fetchall()
            if len(a) > 0:
                i.insert(len(i), True)
            else:
                i.insert(len(i), False)

        # User is loggedin show them the home page
        return render_template('trash_page.html', username=session['username'], folders=folders, folder_id=0,
                               current_space_as_percent=current_space_as_percent,
                               current_space=current_space, max_space=MAX_USER_ALLOCATION)
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



@app.route('/view/<folder_id>/<file_name>', methods=['GET', 'POST'])
def view_file(folder_id, file_name):
    folder = os.path.join(app.config['UPLOAD_FOLDER'], session['id'], folder_id)
    destination = os.path.join(basedir, folder)
    print(file_name + " " + folder_id)
    return send_from_directory(destination, file_name)

@app.route('/download/<folder_id>/<file_name>', methods=['GET', 'POST'])
def download_file(folder_id, file_name):
    folder = os.path.join(app.config['UPLOAD_FOLDER'], session['id'], folder_id)
    destination = os.path.join(basedir, folder)
    return send_file(os.path.join(destination, file_name), as_attachment=True)


def connect_to_db():
    conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
    return conn


def generate_secret_key():
    return secrets.token_urlsafe(16)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'cloudsiteresmi@gmail.com'
app.config['MAIL_PASSWORD'] = 'tliu aepi tjcb pgju'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # Veritabanında e-posta kontrolü
        conn = connect_to_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user_id = cur.fetchone()
        conn.close()

        if user_id:
            # Reset token oluştur
            reset_token = generate_secret_key()

            # Reset token'ı ve süresini veritabanına ekle
            current_time = datetime.now()
            conn = connect_to_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO password_reset_tokens (user_id, token, creation_time, expiration_time) VALUES (%s, %s, %s, %s)",
                        (user_id[0], reset_token, current_time, current_time + timedelta(days=1)))
            conn.commit()
            conn.close()

            # E-posta gönderme işlemi burada gerçekleşecek
            send_reset_email(email, reset_token)

            flash("E-posta adresinize bir bağlantı gönderildi. Lütfen e-postanızı kontrol edin.")
            return render_template('reset_password.html')
        else:
            flash("Bu e-posta adresiyle bir hesap bulunamadı.")
            return render_template('reset_password.html')
    else:
        return render_template('reset_password.html')

def send_reset_email(email, token):
    reset_link = f"{request.host_url}reset_password/{token}"
    click_here_text = f"<a href='{reset_link}'>Buraya tıklayın</a>"

    msg = Message('Parola Sıfırlama', sender='cloudsiteresmi@gmail.com', recipients=[email])
    msg.html = f"""Parolanızı sıfırlamak için lütfen {click_here_text}.

Bağlantının süresi 24 saat içindedir. Eğer parolanızı sıfırlamak istemiyorsanız bu e-postayı görmezden gelebilirsiniz.
"""
    mail.send(msg)


@app.route('/reset_password/<password_reset_token>', methods=['GET', 'POST'])
def reset_password(password_reset_token):
    if request.method == 'POST' and 'new_password' in request.form and 're_password' in request.form:
        conn = connect_to_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id FROM password_reset_tokens WHERE token = %s AND used = FALSE AND expiration_time > now()",
            (password_reset_token,))
        user_id = cur.fetchone()

        if user_id:
            new_password = request.form['new_password']
            re_password = request.form['re_password']

            if new_password == re_password and new_password.strip() != "":
                cur.execute("UPDATE users SET password = %s WHERE id = %s", (generate_password_hash(new_password), user_id[0]))
                conn.commit()

                cur.execute("UPDATE password_reset_tokens SET used = TRUE WHERE token = %s", (password_reset_token,))
                conn.commit()
                conn.close()

                flash("Şifreniz başarıyla güncellendi.")
                return redirect(url_for('login'))
            else:
                flash("Yeni şifreniz ve onay şifreniz eşleşmiyor.")
                return render_template('new_password.html')
        else:
            flash("Geçersiz veya kullanılmış bir bağlantı.")
            return render_template('reset_password.html')
    else:
        conn = connect_to_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT user_id FROM password_reset_tokens WHERE token = %s AND used = FALSE AND expiration_time > now()",
            (password_reset_token,))
        print(password_reset_token)
        user_id = cur.fetchone()
        conn.close()

        if user_id:
            return render_template('new_password.html', password_reset_token=password_reset_token)
        else:
            flash("Geçersiz veya kullanılmış bir bağlantı.")
            return render_template('reset_password.html')


if __name__ == "__main__":
    load_dotenv()
    app.run(debug=True)
    #
