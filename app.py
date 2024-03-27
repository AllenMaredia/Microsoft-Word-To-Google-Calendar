from datetime import datetime, timezone
from calendarParser import extract_events_from_docx, add_events_to_calendar
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, User, UserToken


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SECRET_KEY'] = ''
db.init_app(app)
migrate = Migrate(app, db)


# Configure Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'doc', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Home route
@app.route('/home')
@login_required
def home():
    return render_template('index.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another username.', 'error')
        else:
            new_user = User(username=username, password=generate_password_hash(
                password, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()

            # Create a UserToken for the new user
            user_token = UserToken(user_id=new_user.id)
            db.session.add(user_token)
            db.session.commit()

            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)

            # Check if the user has a corresponding UserToken, create one if not
            user_token = UserToken.query.filter_by(user_id=user.id).first()
            if not user_token:
                user_token = UserToken(user_id=user.id)
                db.session.add(user_token)
                db.session.commit()

            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')


# Logout route
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files['file']
    if file and allowed_file(file.filename):
        events = extract_events_from_docx(file)

        if events:
            # Add events to Google Calendar
            add_events_to_calendar(events)
            # Render the success template
            return render_template('success.html')

    return render_template('error.html')


@app.route('/back_to_index')
@login_required
def back_to_index():
    return redirect(url_for('home'))


@app.route('/authorize')
@login_required
def authorize():
    if current_user.google_calendar_connected:
        flash('Google Calendar is already connected.', 'warning')
        return redirect(url_for('home'))

    client_secret_path = os.path.join(
        os.path.dirname(__file__), 'credentials.json')

    flow = InstalledAppFlow.from_client_secrets_file(
        client_secret_path,
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=url_for('callback', _external=True)
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the session for later verification
    session['oauth_state'] = state

    return redirect(authorization_url)


@app.route('/callback')
@login_required
def callback():
    try:
        client_secret_path = os.path.join(
            os.path.dirname(__file__), 'credentials.json')

        state = session['oauth_state']
        flow = InstalledAppFlow.from_client_secrets_file(
            client_secret_path,
            scopes=['https://www.googleapis.com/auth/calendar'],
            redirect_uri=url_for('callback', _external=True)
        )

        flow.fetch_token(authorization_response=request.url, state=state)

        # Save the user-specific credentials to the database
        user_token = UserToken.query.filter_by(user_id=current_user.id).first()

        # Check if flow.credentials exists and if refresh_token exists before updating UserToken
        if flow.credentials and hasattr(flow.credentials, 'refresh_token') and flow.credentials.refresh_token:
            user_token.refresh_token = flow.credentials.refresh_token
            current_user.google_calendar_connected = True
            db.session.commit()
            flash('Google Calendar connected successfully!', 'success')
        else:
            current_user.google_calendar_connected = True
            db.session.commit()
            flash('Google Calendar connected, but no refresh token received.', 'warning')

    except Exception as e:
        flash(f"Error connecting to Google Calendar: {str(e)}", 'error')

    return redirect(url_for('home'))


@app.route('/revoke_access')
@login_required
def revoke_access():
    user_token = UserToken.query.filter_by(user_id=current_user.id).first()
    if user_token:
        creds = user_token.to_google_credentials()
        creds.revoke(Request())
        user_token.delete()
        db.session.commit()
        flash('Access revoked. Connect Google Calendar again.', 'info')
    else:
        flash('No Google Calendar access to revoke.', 'info')

    return redirect(url_for('index'))


# Flask shell context
@app.shell_context_processor
def make_shell_context():
    return {'app': app, 'db': db, 'User': User, 'UserToken': UserToken}


if __name__ == "__main__":
    app.run(debug=True)
