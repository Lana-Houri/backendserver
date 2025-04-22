from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from db_config import DB_CONFIG
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "default-secret-key")

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define User model (make sure this matches your actual User model)
class User(db.Model):
    __tablename__ = 'user'  # Explicitly set table name
    
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True)
    hashed_password = db.Column(db.String(128))

    def __init__(self, user_name, password):
        self.user_name = user_name
        self.hashed_password = bcrypt.generate_password_hash(password)

# Create admin user
def create_admin_user():
    username = "admin"
    password = "admin123"
    
    with app.app_context():
        # Create tables first
        print("Creating database tables...")
        db.create_all()
        print("Tables created successfully.")
        
        # Check if user already exists
        try:
            existing_user = User.query.filter_by(user_name=username).first()
            if existing_user:
                print(f"User '{username}' already exists.")
                return
            
            # Create new admin user
            new_user = User(user_name=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            print(f"Created admin user: {username}")
            print("You can now log in with:")
            print(f"Username: {username}")
            print(f"Password: {password}")
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    create_admin_user()