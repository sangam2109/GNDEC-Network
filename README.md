# GNDEC Network - Social Platform

A Flask-based social networking platform specifically designed for GNDEC (Guru Nanak Dev Engineering College) students and alumni.

## Features

- **User Authentication**
  - Email-based registration with OTP verification
  - Secure login system
  - Password reset functionality
  - Session management

- **Profile Management**
  - Custom profile pictures
  - Bio and personal information
  - College and course details

- **Social Features**
  - Create, edit, and delete posts
  - Support for text, images, and PDF uploads
  - Like and comment on posts
  - Friend request system
  - News feed showing friends' posts

- **Search Functionality**
  - Find and connect with other users
  - Search by name

## Technology Stack

- **Backend**: Python Flask
- **Database**: MongoDB with MongoEngine ODM
- **Authentication**: Flask-Login
- **Email Service**: Flask-Mail
- **File Handling**: Werkzeug
- **Security**: Password hashing, Token-based verification

## Installation

1. Clone the repository:
```bash
git clone https://github.com/AdarshMishra26/GNDEC-Network.git
cd GNDEC-Network
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following variables:
```env
MONGODB_URI=your_mongodb_connection_string
SECRET_KEY=your_secret_key
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_specific_password
```

5. Create necessary directories:
```bash
mkdir -p static/uploads static/images
```

## Running the Application

1. Start the Flask development server:
```bash
python app.py
```

2. Access the application at `http://localhost:8000`


## Security Features

- Password hashing using Werkzeug
- Email verification for registration
- Secure file upload handling
- CSRF protection
- Session management
- Protected routes with login_required decorator

## Contributing

1. Fork the repository
2. Create a new branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Commit your changes (`git commit -am 'Add new feature'`)
5. Push to the branch (`git push origin feature/improvement`)
6. Create a Pull Request

## Environment Variables

Make sure to set up the following environment variables in your `.env` file:

- `MONGODB_URI`: MongoDB connection string
- `SECRET_KEY`: Flask secret key for session management
- `MAIL_SERVER`: SMTP server for email services
- `MAIL_PORT`: SMTP port number
- `MAIL_USE_TLS`: Boolean for TLS usage
- `MAIL_USERNAME`: Email username
- `MAIL_PASSWORD`: Email password or app-specific password

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, create an issue in the repository.

