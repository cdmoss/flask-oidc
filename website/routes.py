import time
from flask import Blueprint, request, session
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt, check_password_hash, generate_password_hash
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth, generate_user_info


bp = Blueprint('home', __name__)

def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')
    form = request.form
    client_id = gen_salt(24)
    client = OAuth2Client(client_id=client_id, user_id=user.id)
    # Mixin doesn't set the issue_at date
    client.client_id_issued_at = int(time.time())
    if client.token_endpoint_auth_method == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)
    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/login', methods=['GET', 'POST'])
def authorize():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not check_password_hash(user.password, password) or not user:
            return render_template('login.html', error_message='Invalid username or password')        
        
        return authorization.create_authorization_response(grant_user=user)
    return render_template('login.html')

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('password')

        if password != confirm_password:
            return render_template('signup.html', error_message='Passwords do not match')

        if not username or not password:
            return render_template('signup.html', error_message='Username and password are required')

        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error_message='User with that name already exists')

        user = User(username=username, password=generate_password_hash(password))

        db.session.add(user)
        db.session.commit()

        return render_template('register_success.html')

    return render_template('signup.html')

@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/userinfo')
@require_oauth('profile')
def api_me():
    return jsonify(generate_user_info(current_token.user, current_token.scope))
