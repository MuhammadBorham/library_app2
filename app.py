from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import timedelta
import os
from werkzeug.utils import secure_filename
import uuid
# If you find this in your code, remove it
# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')

# PostgreSQL configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin123@localhost/library'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@library.com'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

app.config['UPLOAD_FOLDER'] = 'static/uploads/books'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    penalty = db.Column(db.Float, default=0.0)  # New field for penalties

    # Relationship to BorrowedBook
    borrowed_books = db.relationship('BorrowedBook', back_populates='user')

# Author model
class Author(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    books = db.relationship('Book', backref='author', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    quantity = db.Column(db.Integer, default=1)
    borrowed = db.Column(db.Integer, default=0)
    author_id = db.Column(db.Integer, db.ForeignKey('author.id'), nullable=False)
    image_filename = db.Column(db.String(255))  # New field for image filename
    
    # Relationship to BorrowedBook
    borrowed_by = db.relationship('BorrowedBook', back_populates='book', lazy=True)

class BorrowedBook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    borrowed_at = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)  # New field for due date

    # Relationships
    user = db.relationship('User', back_populates='borrowed_books')
    book = db.relationship('Book', back_populates='borrowed_by')
# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility functions
def send_reset_email(user):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps(user.email, salt='password-reset')
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', recipients=[user.email])
    msg.body = f'To reset your password, visit the following link: {reset_url}'
    mail.send(msg)

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
    except:
        return None
    return User.query.filter_by(email=email).first()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        email = request.form.get('email', '').strip()
        user_type = request.form.get('user_type', 'normal')
        admin_password = request.form.get('admin_password', '').strip()

        print(f"Registration data: {first_name}, {last_name}, {username}, {email}")

        # Validate required fields
        if not first_name or not last_name or not username or not password or not phone_number or not email:
            flash('All fields are required')
            return render_template('register.html')

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')

        # Validate admin registration
        is_admin = user_type == 'admin' and admin_password == os.environ.get('ADMIN_PASSWORD', 'admin123')
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            username=username,
            password=generate_password_hash(password),
            phone_number=phone_number,
            email=email,
            is_admin=is_admin
        )

        print(f"Creating new user: {new_user}")

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error during registration: {e}")
            flash('An error occurred. Please try again.')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip()
        password = request.form['password']

        user = User.query.filter((User.username == login_input) | (User.email == login_input)).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username/email or password')
            return render_template('login.html')  # Render the same page

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('Password reset instructions have been sent to your email.')
            return redirect(url_for('login'))
        else:
            flash('Email not found.')
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = verify_reset_token(token)
    if not user:
        flash('Invalid or expired token')
        return redirect(url_for('reset_password_request'))
    if request.method == 'POST':
        password = request.form['password']
        user.password = generate_password_hash(password)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    welcome_message = f"Welcome, {current_user.first_name} {current_user.last_name}!"
    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)

    # Filter books based on search query
    if search_query:
        books = Book.query.join(Author).filter(
            (Book.title.ilike(f'%{search_query}%')) | (Author.name.ilike(f'%{search_query}%'))
        ).paginate(page=page, per_page=10)
    else:
        books = Book.query.paginate(page=page, per_page=10)

    # Check if the current user has borrowed each book
    for book in books.items:
        book.user_has_borrowed = BorrowedBook.query.filter_by(
            user_id=current_user.id, book_id=book.id
        ).first() is not None

    return render_template('dashboard.html', welcome_message=welcome_message, books=books, search_query=search_query)

@app.route('/book/<int:book_id>')
def book_details(book_id):
    book = Book.query.get_or_404(book_id)
    author = Author.query.get(book.author_id)
    return render_template('book_details.html', book=book, author=author)

@app.route('/my_books')
@login_required
def my_books():
    borrowed_books = BorrowedBook.query.filter_by(user_id=current_user.id).all()
    current_time = datetime.utcnow()  # Pass the current time to the template
    return render_template('my_books.html', borrowed_books=borrowed_books, current_time=current_time)

@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def add_book():
    if not current_user.is_admin:
        flash('You do not have permission to add books')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Handle file upload
        image_file = request.files.get('image')
        image_filename = None
        
        if image_file and image_file.filename != '':
            if allowed_file(image_file.filename):
                # Generate a unique filename
                ext = image_file.filename.rsplit('.', 1)[1].lower()
                image_filename = f"{uuid.uuid4()}.{ext}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
                
                # Create upload folder if it doesn't exist
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                
                # Save the file
                image_file.save(image_path)
            else:
                flash('Allowed image types are: png, jpg, jpeg, gif')
                return redirect(url_for('add_book'))

        title = request.form['title']
        description = request.form.get('description', '')
        quantity = int(request.form['quantity'])
        author_id = request.form.get('author_id')
        new_author_name = request.form.get('new_author_name', '').strip()
        new_author_bio = request.form.get('new_author_bio', '').strip()

        # Validate author selection
        if not author_id and not new_author_name:
            flash('Please select an author or add a new one')
            return redirect(url_for('add_book'))

        # If a new author is provided, create it
        if new_author_name:
            author = Author.query.filter_by(name=new_author_name).first()
            if not author:
                author = Author(name=new_author_name, bio=new_author_bio)
                db.session.add(author)
                db.session.commit()
            author_id = author.id

        # Create new book
        new_book = Book(
            title=title,
            description=description,
            quantity=quantity,
            author_id=author_id,
            image_filename=image_filename
        )

        try:
            db.session.add(new_book)
            db.session.commit()
            flash('Book added successfully')
            return redirect(url_for('add_book'))  # Redirect back to the add_book page
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
            return redirect(url_for('add_book'))

    # Fetch all authors for the dropdown
    authors = Author.query.all()
    return render_template('add_book.html', authors=authors)


@app.route('/author/<int:author_id>')
def author_details(author_id):
    author = Author.query.get_or_404(author_id)
    return render_template('author_details.html', author=author)

@app.route('/remove_author/<int:author_id>',)
@login_required
def remove_author(author_id):
    if not current_user.is_admin:
        flash('You do not have permission to remove authors')
        return redirect(url_for('dashboard'))

    author = Author.query.get(author_id)
    if author:
        if author.books:
            flash('Cannot remove author with associated books')
        else:
            try:
                db.session.delete(author)
                db.session.commit()
                flash('Author removed successfully')
            except Exception as e:
                db.session.rollback()
                flash('An error occurred. Please try again.')
    else:
        flash('Author not found')

    return redirect(url_for('dashboard'))  # Redirect back to the dashboard

@app.route('/remove_book/<int:book_id>', methods=['POST'])
@login_required
def remove_book(book_id):
    if not current_user.is_admin:
        flash('You do not have permission to remove books')
        return redirect(url_for('dashboard'))

    book = Book.query.get(book_id)
    if book:
        try:
            # Delete all BorrowedBook records associated with this book
            BorrowedBook.query.filter_by(book_id=book.id).delete()
            flash('All borrowed records for this book have been deleted.')

            # Now delete the book
            db.session.delete(book)
            db.session.commit()
            flash('Book removed successfully')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
    else:
        flash('Book not found')

    return redirect(url_for('dashboard'))

  # Add this import at the top of the file

@app.route('/borrow_book/<int:book_id>', methods=['POST'])
@login_required
def borrow_book(book_id):
    book = Book.query.get(book_id)
    if book and book.quantity > book.borrowed:
        try:
            book.borrowed += 1
            due_date = datetime.utcnow() + timedelta(days=14)  # Set due date to 14 days from now
            borrowed_book = BorrowedBook(user_id=current_user.id, book_id=book.id, due_date=due_date)
            db.session.add(borrowed_book)
            db.session.commit()
            flash('Book borrowed successfully. Due date: ' + due_date.strftime('%Y-%m-%d'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
    else:
        flash('Book is not available')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/borrowed_books')
@login_required
def borrowed_books():
    if not current_user.is_admin:
        flash('You do not have permission to view this page')
        return redirect(url_for('dashboard'))

    # Fetch all borrowed books with user and book details
    borrowed_books = BorrowedBook.query.join(User).join(Book).all()

    # Group borrowed books by book
    grouped_books = {}
    for borrowed_book in borrowed_books:
        book = borrowed_book.book
        if book not in grouped_books:
            grouped_books[book] = []
        grouped_books[book].append(borrowed_book)

    # Pass the current time to the template
    current_time = datetime.utcnow()
    return render_template('borrowed_books.html', borrowed_books=grouped_books, current_time=current_time)

@app.route('/return_book/<int:book_id>', methods=['POST'])
@login_required
def return_book(book_id):
    book = Book.query.get(book_id)
    if not book:
        flash('Book not found')
        return redirect(url_for('dashboard'))

    # Allow admins to return any book, or users to return their own books
    if current_user.is_admin:
        borrowed_book = BorrowedBook.query.filter_by(book_id=book.id).first()
    else:
        borrowed_book = BorrowedBook.query.filter_by(book_id=book.id, user_id=current_user.id).first()

    if borrowed_book:
        try:
            # Calculate penalty if the book is returned late
            if datetime.utcnow() > borrowed_book.due_date:
                days_late = (datetime.utcnow() - borrowed_book.due_date).days
                penalty = days_late * 0.05  # 5 cents per day
                current_user.penalty += penalty  # Add penalty to the user's account
                flash(f'Book returned late! Penalty: ${penalty:.2f} added to your account.')
            else:
                flash('Book returned successfully')

            book.borrowed -= 1
            db.session.delete(borrowed_book)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
    else:
        flash('You cannot return this book')

    return redirect(request.referrer or url_for('dashboard'))

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)