from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, 
    logout_user, current_user, AnonymousUserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_mongoengine import MongoEngine
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
from mongoengine import *
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import random
import string

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGODB_SETTINGS'] = {
    'host': os.getenv('MONGODB_URI')
}
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Initialize MongoDB and LoginManager
db = MongoEngine(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.anonymous_user = AnonymousUserMixin

# Initialize mail
mail = Mail(app)
mail.init_app(app)

# Add the serializer for token generation
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Define AnonymousUser class before using it
class AnonymousUser(AnonymousUserMixin):
    def get_pending_friend_requests(self):
        return []

    def get_pending_friend_requests_count(self):
        return 0

# User Model
class User(UserMixin, db.Document):
    email = db.StringField(unique=True, required=True)
    password_hash = db.StringField(required=True)
    name = db.StringField(required=True)
    college = db.StringField()
    course = db.StringField()
    profile_picture = db.StringField(default='default.jpg')
    bio = db.StringField(max_length=500)
    friends = db.ListField(db.ReferenceField('User'))
    created_at = db.DateTimeField(default=datetime.utcnow)
    meta = {'collection': 'users'}

    def get_id(self):
        return str(self.id)

    def is_friend(self, other_user):
        """Check if the other user is in the friends list"""
        return other_user in self.friends

    def has_sent_friend_request(self, other_user):
        """Check if a friend request has been sent to the other user"""
        return FriendRequest.objects(
            from_user=self.id,
            to_user=other_user.id,
            status='pending'
        ).first() is not None

    def get_pending_friend_requests(self):
        """Get all pending friend requests sent to this user"""
        return FriendRequest.objects(
            to_user=self.id,
            status='pending'
        )

    def get_pending_friend_requests_count(self):
        """Get the count of pending friend requests"""
        return FriendRequest.objects(
            to_user=self.id,
            status='pending'
        ).count()

    def get_sent_friend_requests(self):
        """Get all pending friend requests sent by this user"""
        return FriendRequest.objects(
            from_user=self.id,
            status='pending'
        )

    @staticmethod
    def get_pending_friend_requests():
        """Default method for anonymous users"""
        return []

    def has_liked_post(self, post):
        """Check if the user has liked a specific post"""
        try:
            return str(self.id) in [str(user_id) for user_id in post.likes]
        except Exception:
            return False

# Define Comment first
class Comment(db.Document):
    content = db.StringField(required=True)
    user_id = db.ReferenceField(User, required=True)
    timestamp = db.DateTimeField(default=datetime.utcnow)

# Then define Post
class Post(db.Document):
    content = db.StringField(required=True)
    file = db.StringField()  # This will store either image or PDF
    file_type = db.StringField()  # 'image' or 'pdf'
    timestamp = db.DateTimeField(default=datetime.utcnow)
    user_id = db.ReferenceField(User, required=True)
    like_ids = db.ListField(db.StringField(), default=list)
    comments = db.ListField(db.ReferenceField(Comment))
    likes = db.ListField(db.ReferenceField(User), default=list)
    meta = {
        'collection': 'posts', 
        'ordering': ['-timestamp'],
        'strict': False  # Allow fields not defined in the model
    }
    
    @property
    def likes_count(self):
        return len(self.like_ids)
        
    def is_liked_by(self, user):
        return str(user.id) in self.like_ids

    def migrate_likes(self):
        """Ensure post has like_ids field"""
        if not hasattr(self, 'like_ids'):
            self.like_ids = []
            self.save()

# Friend Request Model
class FriendRequest(db.Document):
    from_user = db.ReferenceField(User, required=True)
    to_user = db.ReferenceField(User, required=True)
    timestamp = db.DateTimeField(default=datetime.utcnow)
    status = db.StringField(default='pending')  # pending, accepted, rejected
    meta = {'collection': 'friend_requests'}

@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()

@app.route('/')
def index():
    if current_user.is_authenticated:
        # Get posts from current user and their friends
        friend_ids = [friend.id for friend in current_user.friends]
        friend_ids.append(current_user.id)
        posts = Post.objects(user_id__in=friend_ids).order_by('-timestamp')
        return render_template('index.html', posts=posts)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.objects(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid email or password')
    return render_template('login.html')

# Generate OTP
def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Send OTP via email
def send_otp_email(email, otp):
    msg = Message('Email Verification OTP',
                  sender='your-email@example.com',
                  recipients=[email])
    msg.body = f'Your OTP for GNDEC Network registration is: {otp}'
    mail.send(msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        # Check if user already exists using MongoEngine syntax
        user = User.objects(email=email).first()
        if user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        # Generate and send OTP
        otp = generate_otp()
        session['registration_otp'] = otp
        session['registration_email'] = email
        session['registration_password'] = generate_password_hash(password)  # Hash password before storing
        session['registration_name'] = name
        
        try:
            send_otp_email(email, otp)
            return redirect(url_for('verify_otp'))
        except Exception as e:
            print(f"Error sending OTP: {str(e)}")  # Add logging for debugging
            flash('Error sending OTP. Please try again.', 'danger')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'registration_otp' not in session:
        return redirect(url_for('register'))
        
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if user_otp == session['registration_otp']:
            # Create new user using MongoEngine syntax
            try:
                new_user = User(
                    email=session['registration_email'],
                    password_hash=session['registration_password'],
                    name=session['registration_name']
                )
                new_user.save()
                
                # Clear session data
                session.pop('registration_otp', None)
                session.pop('registration_email', None)
                session.pop('registration_password', None)
                session.pop('registration_name', None)
                
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print(f"Error creating user: {str(e)}")  # Add logging for debugging
                flash('Error creating account. Please try again.', 'danger')
                return redirect(url_for('register'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            
    return render_template('verify_otp.html')

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    uploaded_file = request.files.get('file')
    
    if content:
        file_filename = None
        file_type = None
        
        if uploaded_file and allowed_file(uploaded_file.filename):
            file_filename = secure_filename(uploaded_file.filename)
            file_extension = file_filename.rsplit('.', 1)[1].lower()
            
            # Determine file type
            if file_extension == 'pdf':
                file_type = 'pdf'
            else:
                file_type = 'image'
                
            uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_filename))
            
        post = Post(
            content=content,
            file=file_filename,
            file_type=file_type,
            user_id=current_user.id
        )
        post.save()
        flash('Post created successfully!')
    return redirect(url_for('index'))

@app.route('/post/<post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    try:
        post = Post.objects(id=post_id).first_or_404()
        
        # Check if user has already liked the post
        user_liked = current_user.has_liked_post(post)
        
        if user_liked:
            # Unlike the post
            Post.objects(id=post_id).update_one(pull__likes=current_user.id)
            liked = False
        else:
            # Like the post
            Post.objects(id=post_id).update_one(push__likes=current_user.id)
            liked = True
        
        # Get updated post
        post.reload()
        
        return jsonify({
            'status': 'success',
            'liked': liked,
            'likes': len(post.likes)
        })
    except Exception as e:
        print(f"Error in like_post: {str(e)}")  # For debugging
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

@app.route('/post/<post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.objects(id=post_id).first_or_404()
    content = request.form.get('content')
    
    if content:
        # First create and save the comment
        comment = Comment(
            content=content,
            user_id=current_user.id
        )
        comment.save()  # Save the comment first
        
        # Then append the saved comment to the post
        post.comments.append(comment)
        post.save()
        flash('Comment added successfully!')
    return redirect(url_for('index'))

@app.route('/profile/<user_id>')
@login_required
def profile(user_id):
    user = User.objects(id=user_id).first_or_404()
    posts = Post.objects(user_id=user.id).order_by('-timestamp')
    is_friend = user in current_user.friends
    friend_request = FriendRequest.objects(
        from_user=current_user.id,
        to_user=user.id,
        status='pending'
    ).first()
    return render_template('profile.html', user=user, posts=posts, 
                         is_friend=is_friend, friend_request=friend_request)

@app.route('/send_friend_request/<user_id>', methods=['POST'])
@login_required
def send_friend_request(user_id):
    to_user = User.objects(id=user_id).first_or_404()
    
    # Check if request already exists
    existing_request = FriendRequest.objects(
        from_user=current_user.id,
        to_user=to_user.id,
        status='pending'
    ).first()
    
    if existing_request:
        flash('Friend request already sent!')
        return redirect(url_for('profile', user_id=user_id))
    
    if to_user not in current_user.friends:
        friend_request = FriendRequest(
            from_user=current_user.id,
            to_user=to_user.id,
            status='pending'
        )
        friend_request.save()
        flash('Friend request sent!')
    return redirect(url_for('profile', user_id=user_id))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        users = User.objects(name__icontains=query)
        return render_template('search.html', users=users, query=query)
    return render_template('search.html', users=None, query=None)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        try:
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename != '':
                    print(f"Uploading file: {file.filename}")
                    filename = f"profile_{current_user.id}_{secure_filename(file.filename)}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    print(f"File saved to: {file_path}")
                    current_user.profile_picture = filename
                    print(f"Profile picture updated in database: {filename}")
            
            current_user.save()
            return redirect(url_for('settings'))
            
        except Exception as e:
            print(f"Error in file upload: {str(e)}")
            flash('Error uploading file')
            
    return render_template('settings.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/developer')
def developer():
    return render_template('developer.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Utility functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def migrate_posts_likes():
    """Migrate all posts from likes to like_ids"""
    try:
        posts = Post.objects()
        for post in posts:
            post.migrate_likes()
        print("Posts migration completed successfully")
    except Exception as e:
        print(f"Error during migration: {str(e)}")

@app.route('/friend-request/<int:user_id>', methods=['POST'])
@login_required
def send_friend_request_endpoint(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.is_friend(user):
        flash('You are already friends!', 'info')
    elif current_user.has_sent_friend_request(user):
        flash('Friend request already sent!', 'info')
    else:
        friend_request = FriendRequest(sender_id=current_user.id, receiver_id=user_id)
        db.session.add(friend_request)
        db.session.commit()
        flash('Friend request sent!', 'success')
    return redirect(url_for('profile', user_id=user_id))

@app.route('/accept-friend-request/<int:request_id>', methods=['POST'])
@login_required
def accept_friend_request_sql(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    if friend_request.receiver_id != current_user.id:
        abort(403)
    
    # Add to friends
    current_user.friends.append(friend_request.sender)
    friend_request.sender.friends.append(current_user)
    
    # Update request status
    friend_request.status = 'accepted'
    db.session.commit()
    
    flash('Friend request accepted!', 'success')
    return redirect(url_for('profile', user_id=friend_request.sender_id))

@app.route('/friend_requests')
@login_required
def friend_requests():
    # Get pending requests without using select_related
    pending_requests = FriendRequest.objects(
        to_user=current_user.id,
        status='pending'
    )
    
    # Add debug logging
    print(f"Found {pending_requests.count()} pending requests for user {current_user.id}")
    
    return render_template('friend_requests.html', requests=pending_requests)

@app.route('/accept_friend_request/<request_id>', methods=['POST'])
@login_required
def accept_friend_request(request_id):
    friend_request = FriendRequest.objects(id=request_id).first_or_404()
    
    if friend_request.to_user.id != current_user.id:
        flash('Invalid friend request')
        return redirect(url_for('friend_requests'))
    
    # Get both users
    from_user = User.objects(id=friend_request.from_user.id).first()
    to_user = User.objects(id=current_user.id).first()
    
    # Add each user to the other's friends list
    User.objects(id=current_user.id).update(add_to_set__friends=from_user)
    User.objects(id=from_user.id).update(add_to_set__friends=to_user)
    
    # Update request status
    friend_request.status = 'accepted'
    friend_request.save()
    
    flash('Friend request accepted!')
    return redirect(url_for('friend_requests'))

@app.route('/reject_friend_request/<request_id>', methods=['POST'])
@login_required
def reject_friend_request(request_id):
    friend_request = FriendRequest.objects(id=request_id).first_or_404()
    
    if friend_request.to_user.id != current_user.id:
        flash('Invalid friend request')
        return redirect(url_for('friend_requests'))
    
    friend_request.status = 'rejected'
    friend_request.save()
    
    flash('Friend request rejected')
    return redirect(url_for('friend_requests'))

@app.route('/post/<post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.objects(id=post_id).first_or_404()
    
    if str(post.user_id.id) != str(current_user.id):
        flash('You can only edit your own posts!')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        content = request.form.get('content')
        uploaded_file = request.files.get('file')
        
        if content:
            post.content = content
            
            if uploaded_file and allowed_file(uploaded_file.filename):
                # Delete old file if exists
                if post.file:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], post.file)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                # Save new file
                file_filename = secure_filename(uploaded_file.filename)
                file_extension = file_filename.rsplit('.', 1)[1].lower()
                
                # Determine file type
                if file_extension == 'pdf':
                    post.file_type = 'pdf'
                else:
                    post.file_type = 'image'
                    
                uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_filename))
                post.file = file_filename
            
            post.save()
            flash('Post updated successfully!')
            return redirect(url_for('index'))
            
    return render_template('edit_post.html', post=post)

def send_reset_email(user_email):
    token = serializer.dumps(user_email, salt='password-reset-salt')
    reset_url = url_for('reset_password', token=token, _external=True)
    
    subject = 'Password Reset Request'
    body = f'''Dear User,

You have requested to reset your password for your GNDEC Connect account.

To reset your password, please click on the following link:
{reset_url}

This link will expire in 1 hour.

If you did not make this request, please ignore this email and no changes will be made to your account.

Best regards,
GNDEC Connect Team'''

    msg = Message(subject,
                 sender=app.config['MAIL_USERNAME'],
                 recipients=[user_email],
                 body=body)
    mail.send(msg)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.objects(email=email).first()
        
        if user:
            try:
                send_reset_email(email)
                flash('Password reset link has been sent to your email.', 'success')
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Error sending reset email. Please try again later.', 'error')
        else:
            flash('Email address not found.', 'error')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html')
        
        user = User.objects(email=email).first()
        if user:
            user.password_hash = generate_password_hash(password)
            user.save()
            flash('Your password has been updated! Please login with your new password.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/post/<post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.objects(id=post_id).first_or_404()
    
    # Check if the current user is the post owner
    if str(post.user_id.id) != str(current_user.id):
        flash('You can only delete your own posts!', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Delete associated file if exists
        if post.file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], post.file)
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Delete all comments associated with the post
        for comment in post.comments:
            comment.delete()
        
        # Delete the post
        post.delete()
        
        flash('Post deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting post: {str(e)}")
        flash('Error deleting post. Please try again.', 'danger')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(os.path.join('static', 'uploads'), exist_ok=True)
    os.makedirs(os.path.join('static', 'images'), exist_ok=True)
    
    # Migrate posts
    migrate_posts_likes()
    
    app.run(debug=True, port=8000)
