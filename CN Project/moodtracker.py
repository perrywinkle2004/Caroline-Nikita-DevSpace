from app import app
from flask import flash, redirect, render_template, request, session, url_for

# Dummy database for mood tracking
user_moods = {}  # This can be stored in a real database in a production environment

@app.route('/moodtracker', methods=['GET', 'POST'])
def moodtracker():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if the user is not authenticated

    username = session['username']

    if request.method == 'POST':
        # Capture the user's mood and date from the form
        mood = request.form['mood']
        date = request.form['date']  # Capture the selected date

        # Ensure user_moods dictionary is initialized for this user
        if username not in user_moods:
            user_moods[username] = []

        # Store the mood data
        user_moods[username].append({'date': date, 'mood': mood})

        # Flash success message
        flash(f"Mood for {date}: {mood} saved!", category='success')

    # Retrieve and pass the user's mood history for display
    moods = user_moods.get(username, [])

    return render_template('moodtracker.html', moods=moods)
