import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Configuration ---
app = Flask(__name__)
# IMPORTANT: In a real app, use a long, complex secret key from environment variables.
app.secret_key = 'super_secret_dev_key_piano_scores_12345'
DATABASE = 'piano_scores.db'

# --- Database Helper Functions ---


def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # This allows accessing columns by name
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initializes the database schema and seeds some data."""
    with app.app_context():
        db = get_db()
        # Drop tables to ensure a clean start for testing
        db.executescript("""
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS composers;
            DROP TABLE IF EXISTS scores;
            DROP TABLE IF EXISTS favorites;
        """)

        # Create Tables
        with app.open_resource('database_schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())

        # Seed Data
        # User
        hashed_password = generate_password_hash("password123")
        db.execute("INSERT INTO users (name, password) VALUES (?, ?)",
                   ("testuser", hashed_password))

        # Composers
        db.execute("INSERT INTO composers (name, photo_location) VALUES (?, ?)",
                   ("Ludwig van Beethoven", "https://placehold.co/150x150/505050/ffffff?text=Beethoven"))
        db.execute("INSERT INTO composers (name, photo_location) VALUES (?, ?)",
                   ("Frédéric Chopin", "https://placehold.co/150x150/505050/ffffff?text=Chopin"))

        # Scores
        db.execute("INSERT INTO scores (name, composer_id, pdf_location, preview_location) VALUES (?, ?, ?, ?)",
                   ("Moonlight Sonata (1st Mov.)", 1, "/static/pdf/moonlight.pdf", "https://placehold.co/200x280/D8C3A5/404040?text=Moonlight+Page+1"))
        db.execute("INSERT INTO scores (name, composer_id, pdf_location, preview_location) VALUES (?, ?, ?, ?)",
                   ("Nocturne in E-flat major, Op. 9, No. 2", 2, "/static/pdf/nocturne.pdf", "https://placehold.co/200x280/D8C3A5/404040?text=Nocturne+Page+1"))
        db.execute("INSERT INTO scores (name, composer_id, pdf_location, preview_location) VALUES (?, ?, ?, ?)",
                   ("Für Elise", 1, "/static/pdf/fur_elise.pdf", "https://placehold.co/200x280/D8C3A5/404040?text=Elise+Page+1"))
        db.execute("INSERT INTO scores (name, composer_id, pdf_location, preview_location) VALUES (?, ?, ?, ?)",
                   ("Minute Waltz", 2, "/static/pdf/min_waltz.pdf", "https://placehold.co/200x280/D8C3A5/404040?text=Waltz+Page+1"))

        db.commit()


# Run initialization once when the app starts (or manually)
with app.app_context():
    if not os.path.exists(DATABASE):
        init_db()

# --- Authentication Decorator ---


def login_required(f):
    """Decorator to require login for a route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Redirect to login if user is not logged in
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Context Processor (for global variables like login status) ---


@app.context_processor
def inject_user_info():
    """Injects user information into all templates."""
    user_id = session.get('user_id')
    user = None
    if user_id:
        db = get_db()
        user = db.execute('SELECT name FROM users WHERE id = ?', (user_id,)).fetchone()
    return {'logged_in_user': user}

# --- Routes ---


@app.route('/')
@login_required
def index():
    """Main page: All Scores with pagination."""
    db = get_db()

    # --- Pagination ---
    page = request.args.get('page', 1, type=int)
    per_page = 24
    offset = (page - 1) * per_page

    # Fetch only a single page
    scores = db.execute("""
        SELECT s.id, s.name, s.preview_location, c.name AS composer_name
        FROM scores s
        JOIN composers c ON s.composer_id = c.id
        ORDER BY s.id
        LIMIT ? OFFSET ?
    """, (per_page, offset)).fetchall()

    # Get total count for pagination
    total_scores = db.execute("SELECT COUNT(*) AS total FROM scores").fetchone()['total']
    total_pages = (total_scores + per_page - 1) // per_page  # ceil

    return render_template(
        'index.html',
        scores=scores,
        page=page,
        total_pages=total_pages,
        title='All Piano Scores'
    )

# --- AUTHENTICATION ROUTES ---


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page handler."""
    if 'user_id' in session:
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT id, name, password FROM users WHERE name = ?',
                          (username,)).fetchone()

        if user is None:
            error = 'Incorrect username or password.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect username or password.'
        else:
            session.clear()
            session['user_id'] = user['id']
            # Redirect to index or the 'next' page if provided
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page handler."""
    if 'user_id' in session:
        return redirect(url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        db = get_db()
        if not username or not password:
            error = 'Username and Password are required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        elif db.execute('SELECT id FROM users WHERE name = ?', (username,)).fetchone() is not None:
            error = f'User {username} is already taken.'
        else:
            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (name, password) VALUES (?, ?)',
                       (username, hashed_password))
            db.commit()
            return redirect(url_for('login'))

    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.clear()
    return redirect(url_for('login'))

# --- APPLICATION ROUTES (Require Login) ---


@app.route('/score/<int:score_id>')
@login_required
def score_details(score_id):
    """Individual score detail page."""
    user_id = session['user_id']
    db = get_db()

    score = db.execute("""
        SELECT s.id, s.name, s.pdf_location, s.preview_location,
               c.name as composer_name, c.id as composer_id
        FROM scores s
        JOIN composers c ON s.composer_id = c.id
        WHERE s.id = ?
    """, (score_id,)).fetchone()

    if score is None:
        return render_template('error.html', message='Score not found'), 404

    is_favorite = db.execute("""
        SELECT 1 FROM favorites
        WHERE user_id = ? AND score_id = ?
    """, (user_id, score_id)).fetchone() is not None

    return render_template('score_details.html', score=score, is_favorite=is_favorite, title=score['name'])


@app.route('/composers')
@login_required
def composers_list():
    """List of all composers."""
    db = get_db()
    composers = db.execute('SELECT id, name, photo_location FROM composers ORDER BY id').fetchall()
    return render_template('composers_list.html', composers=composers, title='Composers')


@app.route('/composer/<int:composer_id>')
@login_required
def composer_scores(composer_id):
    """All scores by a specific composer."""
    db = get_db()

    composer = db.execute('SELECT name FROM composers WHERE id = ?', (composer_id,)).fetchone()
    if composer is None:
        return render_template('error.html', message='Composer not found'), 404

    scores = db.execute("""
    SELECT s.id, s.name, s.preview_location, c.name AS composer_name
    FROM scores s
    JOIN composers c ON s.composer_id = c.id
    WHERE composer_id = ?
    """, (composer_id,)).fetchall()

    return render_template('composer_scores.html', composer=composer, scores=scores, title=f"Scores by {composer['name']}")


@app.route('/favorites')
@login_required
def favorites():
    """User's favorite scores."""
    user_id = session['user_id']
    db = get_db()

    favorite_scores = db.execute("""
        SELECT s.id, s.name, s.preview_location, c.name as composer_name
        FROM scores s
        JOIN favorites f ON s.id = f.score_id
        JOIN composers c ON s.composer_id = c.id
        WHERE f.user_id = ?
        ORDER BY s.name
    """, (user_id,)).fetchall()

    return render_template('favorites.html', scores=favorite_scores, title='My Favorites')

# --- API Endpoints for AJAX (e.g., toggling favorite status) ---


@app.route('/toggle_favorite/<int:score_id>', methods=['POST'])
@login_required
def toggle_favorite(score_id):
    """Toggles the favorite status of a score."""
    user_id = session['user_id']
    db = get_db()

    is_favorite = db.execute("""
        SELECT 1 FROM favorites
        WHERE user_id = ? AND score_id = ?
    """, (user_id, score_id)).fetchone()

    if is_favorite:
        # Remove from favorites
        db.execute('DELETE FROM favorites WHERE user_id = ? AND score_id = ?', (user_id, score_id))
        message = 'Removed from Favorites.'
    else:
        # Add to favorites
        db.execute('INSERT INTO favorites (user_id, score_id) VALUES (?, ?)', (user_id, score_id))
        message = 'Added to Favorites!'

    db.commit()

    # Simple JSON response for frontend update
    return {'success': True, 'action': 'removed' if is_favorite else 'added', 'message': message}


if __name__ == '__main__':
    # Initialize the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
