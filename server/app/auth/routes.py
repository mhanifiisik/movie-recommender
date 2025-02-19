from flask import request, redirect, url_for, flash, render_template, session
from flask_login import UserMixin, login_user, logout_user, login_required, current_user
from app.supabase_client import supabase
from . import bp, login_manager

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data.id)
        self.email = user_data.email
        metadata = getattr(user_data, 'app_metadata', {}) or {}
        self.auth_provider = metadata.get('provider', 'email')
        # Store additional session data if available
        self.session_data = getattr(user_data, 'session', None)

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    try:
        # Try to get the session token
        access_token = session.get('access_token')
        if access_token:
            # Use the token to get user data
            response = supabase.auth.get_user(access_token)
            if response and response.user:
                return User(response.user)
    except Exception as e:
        print(f"Error loading user: {str(e)}")
    return None

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "email": email,
                    }
                }
            })
            
            if auth_response.user:
                user = User(auth_response.user)
                login_user(user)
                flash('Registration successful!', 'success')
                return redirect(url_for('main.index'))
            
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('auth/register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if auth_response and hasattr(auth_response, 'user') and auth_response.user:
                user = User(auth_response.user)
                login_user(user)
                flash('Login successful!', 'success')
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'): 
                    return redirect(next_page)
                return redirect(url_for('main.index'))
                
        except Exception as e:
            flash(f'Login failed: {str(e)}', 'error')
    
    return render_template('auth/login.html')

@bp.route('/login/google')
def google_login():
    try:
        next_page = request.args.get('next')
        if next_page:
            session['next'] = next_page

        redirect_uri = url_for('auth.oauth_callback', _external=True)
        
        auth_url = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": redirect_uri,
                "scopes": "email profile",
                "query_params": {
                    "access_type": "offline",
                    "prompt": "consent"
                }
            }
        })
        return redirect(auth_url.url)
    except Exception as e:
        flash(f'Google login failed: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@bp.route('/login/github')
def github_login():
    try:
        auth_url = supabase.auth.sign_in_with_oauth({
            "provider": "github",
            "options": {
                "redirect_to": url_for('auth.oauth_callback', _external=True),
                "scopes": "user:email"
            }
        })
        return redirect(auth_url.url)
    except Exception as e:
        flash(f'GitHub login failed: {str(e)}', 'error')
        return redirect(url_for('auth.login'))

@bp.route('/oauth-callback')
def oauth_callback():
    try:
        code = request.args.get('code')
        
        if not code:
            flash('Authentication failed: No code received', 'error')
            return redirect(url_for('auth.login'))

        auth_response = supabase.auth.exchange_code_for_session({
            "auth_code": code
        })
        
        if auth_response and hasattr(auth_response, 'user') and auth_response.user:
            user = User(auth_response.user)
            login_user(user, remember=True)
            
            session['access_token'] = auth_response.session.access_token
            session['refresh_token'] = auth_response.session.refresh_token
            
            flash('Login successful!', 'success')
            
            next_page = session.pop('next', None)
            return redirect(next_page if next_page else url_for('main.index'))
        else:
            flash('Authentication failed: Invalid response', 'error')
            
    except Exception as e:
        print(f"Error during OAuth callback: {str(e)}")
        flash(f'Authentication failed: {str(e)}', 'error')
    
    return redirect(url_for('auth.login'))

@bp.route('/logout')
@login_required
def logout():
    try:
        supabase.auth.sign_out()
        session.pop('access_token', None)
        session.pop('refresh_token', None)
        logout_user()
        flash('Logged out successfully.', 'success')
    except Exception as e:
        flash(f'Logout failed: {str(e)}', 'error')
    return redirect(url_for('auth.login'))

@bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html') 