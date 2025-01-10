import random
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from functools import wraps
from datetime import timedelta
import re
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize SocketIO
socketio = SocketIO(app)

# Dummy databases
users_db = {}
user_moods = {}
login_attempts = {}
user_game_scores = {}

# Update score after each mini-game
@app.route('/update_score', methods=['POST'])
def update_score():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    game_name = request.form['game_name']
    score = int(request.form['score'])

    if username not in user_game_scores:
        user_game_scores[username] = {}
    
    user_game_scores[username][game_name] = score

    # Emit score update via WebSocket to clients
    socketio.emit('score_update', {'username': username, 'game_name': game_name, 'score': score}, broadcast=True)
    
    flash(f'Score for {game_name} saved!', category='success')
    return redirect(url_for('dashboard'))

@app.route('/get_score/<game_name>', methods=['GET'])
def get_score(game_name):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    score = user_game_scores.get(username, {}).get(game_name, 'No score yet')

    return jsonify({'game_name': game_name, 'score': score})

# Session configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Rate limiting decorator
def rate_limit(max_attempts):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            username = request.form.get('username')
            if username:
                attempts = login_attempts.get(username, 0)
                if attempts >= max_attempts:
                    flash('Too many login attempts. Please try again later.', category='error')
                    return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_attempts=5)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_db.get(username)

        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session.permanent = True
            flash('Login successful!', category='success')
            login_attempts[username] = 0
            return redirect(url_for('dashboard'))
        else:
            login_attempts[username] = login_attempts.get(username, 0) + 1
            flash('Invalid username or password. Please try again.', category='error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash('Invalid email format. Please try again.', category='error')
        elif len(password) < 8 or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash('Password must be at least 8 characters long and include a special character.', category='error')
        elif username in users_db:
            flash('Username already exists, please choose another one.', category='error')
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', category='error')
        else:
            users_db[username] = {
                'email': email,
                'password': generate_password_hash(password)
            }
            user_moods[username] = []
            flash('Registration successful! Please log in.', category='success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        flash('If this email is registered, a password reset link has been sent.', 'info')
        return redirect(url_for('password_reset_confirmation'))
    return render_template('forgot_password.html')

@app.route('/password_reset_confirmation')
def password_reset_confirmation():
    return render_template('password_reset_confirmation.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    return render_template('dashboard.html', username=username)

@app.route('/mood-tracker', methods=['GET', 'POST'])
def mood_tracker():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    if request.method == 'POST':
        date = request.form['date']
        mood = request.form['mood']
        if mood and date:
            if username not in user_moods:
                user_moods[username] = []
            user_moods[username].append({'date': date, 'mood': mood})
            flash(f'Mood "{mood}" saved for {date}!', category='success')
        else:
            flash('Please fill in both date and mood!', category='error')

    moods = user_moods.get(username, [])
    return render_template('mood_tracker.html', moods=moods)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', category='success')
    return redirect(url_for('home'))

@app.route('/mini_games')
def mini_games():
    return render_template('mini_games.html')

@app.route('/quiz')
def quiz():
    return render_template('index.html')

@app.route('/memory_match', methods=['GET', 'POST'])
def memory_match():
    if request.method == 'POST':
        difficulty = request.json.get('difficulty', 'easy')
        cards = 8 if difficulty == 'easy' else 16 if difficulty == 'medium' else 24
        # Add logic for game initialization based on `cards`
        return jsonify({'message': 'Memory Match game started', 'cards': cards})

    return render_template('memory_match.html')


@app.route('/hangman', methods=['GET', 'POST'])
def hangman():
    if request.method == 'POST':
        difficulty = request.json.get('difficulty', 'easy')
        word_list = {
    'easy': ["apple", "ball", "cat"],
    'medium': ["elephant", "giraffe", "dolphin"],
    'hard': ["pneumonia", "rhythm", "mnemonic"]
}

        word_list = get_word_list(difficulty)
        # Select a word from `word_list` and start the game
        return jsonify({'message': 'Hangman game started', 'words': word_list})
    return render_template('hangman.html')



@app.route('/daily_challenges')
def daily_challenges():
    joke = ""
    try:
        joke_response = requests.get('https://v2.jokeapi.dev/joke/Any', timeout=5)
        joke_response.raise_for_status()
        joke_data = joke_response.json()
        if joke_data.get('type') == 'single':
            joke = joke_data.get('joke', 'No joke available.')
        else:
            joke = f"{joke_data.get('setup')} - {joke_data.get('delivery')}"
    except requests.RequestException:
        joke = "Couldn't fetch a joke at the moment."

    riddle_list = [
        "I speak without a mouth and hear without ears. I have nobody, but I come alive with wind. What am I?",
        "The more of this there is, the less you see. What is it?",
        "I am not alive, but I grow; I don’t have lungs, but I need air; I don’t have a mouth, but water kills me. What am I?"
    ]
    riddle = random.choice(riddle_list)

    return render_template('daily_challenges.html', riddle=riddle, joke=joke)

@app.route('/jokes')
def jokes():
    return render_template('jokes.html')  # Replace with the actual jokes page template

@app.route('/riddles')
def riddles():
    return render_template('riddles.html')  # Replace with the actual riddles page template

# WebSocket handling
@socketio.on('update_score')
def handle_update_score(data):
    username = session.get('username')
    if not username:
        return False  # Unauthorized request

    game_name = data['game_name']
    score = int(data['score'])

    if username not in user_game_scores:
        user_game_scores[username] = {}
    user_game_scores[username][game_name] = score

    # Emit score update to all connected clients
    emit('score_update', {'username': username, 'game_name': game_name, 'score': score}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
