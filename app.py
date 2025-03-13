from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import or_


# Initialize Flask App
app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///praj.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'HJBSCADSYFCUCGADHSCBGGKYERbjcsduvhdiybmkfgbj;klnjkmNJKLVHJKVGH46556K;KJI1B'  # Required for session handling

# Initialize SQLAlchemy
db = SQLAlchemy(app)

#==========================================================================================================
# Models



# User Model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # "admin" or "user"

    scores = db.relationship('Score', back_populates='user')
    

    # Performance tracking fields
    total_attempts = db.Column(db.Integer, default=0)
    average_score = db.Column(db.Float, default=0.0)

# Subject Model
class Subject(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    
    chapters = db.relationship('Chapter', back_populates='subject')

# Chapter Model
class Chapter(db.Model):
    __tablename__ = 'chapters'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)

    subject = db.relationship('Subject', back_populates='chapters')
    quizzes = db.relationship('Quiz', back_populates='chapter')

    # Track total attempts per chapter
    total_attempts = db.Column(db.Integer, default=0)

# Quiz Model
class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapters.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    duration = db.Column(db.Integer, nullable=False)

    chapter = db.relationship('Chapter', back_populates='quizzes')
    questions = db.relationship('Question', back_populates='quiz', lazy=True)
    scores = db.relationship('Score', back_populates='quiz')
    
    # Performance tracking for quizzes
    total_attempts = db.Column(db.Integer, default=0)
    average_score = db.Column(db.Float, default=0.0)

# Question Model
class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_1 = db.Column(db.String(255), nullable=False)
    option_2 = db.Column(db.String(255), nullable=False)
    option_3 = db.Column(db.String(255), nullable=False)
    option_4 = db.Column(db.String(255), nullable=False)
    correct_option = db.Column(db.Integer, nullable=False)  # 1, 2, 3, or 4
    
    quiz = db.relationship('Quiz', back_populates='questions')

# Score Model
class Score(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    attempt_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', back_populates='scores')
    quiz = db.relationship('Quiz', back_populates='scores')

# class QuizAttempt(db.Model):
#     __tablename__ = 'quiz_attempts'
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
#     score = db.Column(db.Integer, nullable=False)
#     attempt_date = db.Column(db.DateTime, default=datetime.utcnow)

#     user = db.relationship('User', back_populates='quiz_attempts')
#     quiz = db.relationship('Quiz', back_populates='attempts')


#==========================================================================================================
# Initialization of Database and Default Data Setup
with app.app_context():
    db.create_all()

    # Add default admin user if it doesn't exist
    admin_user = User.query.filter_by(email='admin@gmail.com').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            email='admin@gmail.com',
            password=generate_password_hash('123'),
            full_name='Admin User',
            role='admin'  # Assigning admin role
        )
        db.session.add(admin_user)

    db.session.commit()

#==========================================================================================================
# Routes
    
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')

            if user.username == 'admin':
                return redirect(url_for('ad'))  # Redirect to admin dashboard
            else:
                return redirect(url_for('ud'))  # Redirect to user dashboard
            
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        full_name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Username already taken!', 'warning')
            return redirect(url_for('register'))
        if existing_email:
            flash('Email already registered!', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, full_name=full_name, email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/ad')
def ad():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    admin = User.query.get(session['user_id'])
    if not admin or admin.role != 'admin':
        return redirect(url_for('home'))

    total_users = User.query.count()
    total_subjects = Subject.query.count()
    total_quizzes = Quiz.query.count()
    total_questions = Question.query.count()

    return render_template(
        'ad_dash.html',
        total_users=total_users,
        total_subjects=total_subjects,
        total_quizzes=total_quizzes,
        total_questions=total_questions
    )



 #✅ Function to check if user is admin
def is_admin(user_id):
    user = User.query.get(user_id)
    return user and user.role == 'admin'

# 🔹 Manage Users (with Search)
@app.route('/admin/users')
def manage_users():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()

    # Fetch users based on search query
    if search_query:
        users = User.query.filter(User.username.ilike(f"%{search_query}%")).all()
    else:
        users = User.query.all()

    # Fetch quiz attempts only for users with role 'user'
    user_ids = [user.id for user in users if user.role == 'user']
    quiz_attempts = {user_id: [] for user_id in user_ids}  # Default empty list

    if user_ids:
        attempts = Score.query.filter(Score.user_id.in_(user_ids)).all()
        for attempt in attempts:
            quiz_attempts[attempt.user_id].append(attempt)

    return render_template('ad_users.html', users=users, search_query=search_query, quiz_attempts=quiz_attempts)







@app.route('/admin/subjects', methods=['GET', 'POST'])
def manage_subjects():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()  # Get search input

    if request.method == 'POST':  # Adding a new subject
        name = request.form.get('name').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash("Subject name is required!", "danger")
        else:
            new_subject = Subject(name=name, description=description)
            db.session.add(new_subject)
            db.session.commit()
            flash("Subject added successfully!", "success")
            return redirect(url_for('manage_subjects'))

    # Filter subjects if search query exists
    if search_query:
        subjects = Subject.query.filter(Subject.name.ilike(f"%{search_query}%")).all()
    else:
        subjects = Subject.query.all()

    return render_template('ad_subject.html', subjects=subjects, search_query=search_query)

# 🔹 Delete Subject
@app.route('/admin/subjects/delete/<int:subject_id>', methods=['POST'])
def delete_subject(subject_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    subject = Subject.query.get(subject_id)
    if subject:
        db.session.delete(subject)
        db.session.commit()
        flash("Subject deleted successfully!", "success")
    else:
        flash("Subject not found!", "danger")

    return redirect(url_for('manage_subjects'))

# 🔹 Edit Subject
@app.route('/admin/subjects/edit/<int:subject_id>', methods=['POST'])
def edit_subject(subject_id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    subject = Subject.query.get(subject_id)
    if subject:
        subject.name = request.form.get('name').strip()
        subject.description = request.form.get('description').strip()
        db.session.commit()
        flash("Subject updated successfully!", "success")
    else:
        flash("Subject not found!", "danger")

    return redirect(url_for('manage_subjects'))


# ✅ Manage Chapters (CRUD)
@app.route('/admin/chapters', methods=['GET', 'POST'])
def manage_chapters():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()  
    subjects = Subject.query.all()

    if search_query:
        chapters = Chapter.query.filter(
    or_(
        Chapter.name.ilike(f"% {search_query} %"),  # Exact word match
        Chapter.name.ilike(f"{search_query} %"),   # Starts with search term
        Chapter.name.ilike(f"% {search_query}"),   # Ends with search term
        Chapter.name.ilike(f"%{search_query}%")    # General substring match
    )
).all()  # Matches exact words
    else:
        chapters = Chapter.query.all()

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        subject_id = request.form.get('subject_id')

        if name and subject_id:
            new_chapter = Chapter(name=name, description=description, subject_id=subject_id)
            db.session.add(new_chapter)
            db.session.commit()
            flash("Chapter added successfully!", "success")
        else:
            flash("Please provide all required fields!", "danger")

        return redirect(url_for('manage_chapters'))

    return render_template('ad_chapter.html', chapters=chapters, subjects=subjects, search_query=search_query)


# ✅ Edit Chapter Route
@app.route('/admin/chapters/edit/<int:id>', methods=['POST'])
def edit_chapter(id):
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    chapter = Chapter.query.get_or_404(id)

    name = request.form.get('name')
    description = request.form.get('description')
    subject_id = request.form.get('subject_id')

    if name and subject_id:
        chapter.name = name
        chapter.description = description
        chapter.subject_id = subject_id

        db.session.commit()
        flash("Chapter updated successfully!", "success")
    else:
        flash("Please provide all required fields!", "danger")

    return redirect(url_for('manage_chapters'))


# ✅ Delete Chapter Route
@app.route('/admin/chapters/delete/<int:id>', methods=['POST'])
def delete_chapter(id):
    chapter = Chapter.query.get_or_404(id)
    db.session.delete(chapter)
    db.session.commit()
    flash("Chapter deleted successfully!", "success")
    return redirect(url_for('manage_chapters'))



@app.route('/admin/quizzes', methods=['GET', 'POST'])
def manage_quizzes():
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash("Access Denied!", "danger")
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()
    chapters = Chapter.query.all()  # Load chapters for dropdown

    if search_query:
        quizzes = Quiz.query.join(Chapter).filter(Chapter.name.ilike(f"%{search_query}%")).all()
    else:
        quizzes = Quiz.query.all()

    if request.method == 'POST':
        chapter_id = request.form.get('chapter_id')
        date = request.form.get('date')
        duration = request.form.get('duration')

        if chapter_id and date and duration:
            new_quiz = Quiz(
                chapter_id=chapter_id, 
                date=datetime.strptime(date, "%Y-%m-%d"), 
                duration=int(duration)
            )
            db.session.add(new_quiz)
            db.session.commit()
            flash("Quiz added successfully!", "success")
        else:
            flash("Please fill all fields!", "danger")

        return redirect(url_for('manage_quizzes'))

    return render_template('ad_quiz.html', quizzes=quizzes, chapters=chapters, search_query=search_query)



@app.route('/admin/quizzes/delete/<int:id>', methods=['POST'])
def delete_quiz(id):
    quiz = Quiz.query.get_or_404(id)
    db.session.delete(quiz)
    db.session.commit()
    flash("Quiz deleted successfully!", "success")
    return redirect(url_for('manage_quizzes'))

# View all questions for a quiz
@app.route('/admin/questions/<int:quiz_id>')
def manage_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter = quiz.chapter  # Assuming the Quiz model has a relationship with Chapter

    questions = quiz.questions  # Fetch related questions
    return render_template('ad_questions.html', quiz=quiz, questions=questions, chapter=chapter)


# Add a new question
@app.route('/admin/questions/add/<int:quiz_id>', methods=['GET', 'POST'])
def add_question(quiz_id):
    if request.method == 'POST':
        question_text = request.form['question_text']
        option_1 = request.form['option_1']
        option_2 = request.form['option_2']
        option_3 = request.form['option_3']
        option_4 = request.form['option_4']
        correct_option = request.form['correct_option']

        new_question = Question(
            quiz_id=quiz_id, 
            question_text=question_text,
            option_1=option_1,
            option_2=option_2,
            option_3=option_3,
            option_4=option_4,
            correct_option=int(correct_option)
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('manage_questions', quiz_id=quiz_id))

    return render_template('add_question.html', quiz_id=quiz_id)  # Use a new template


@app.route('/admin/questions/edit/<int:question_id>', methods=['POST'])
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)

    # Update fields
    question.question_text = request.form['question_text']
    question.option_1 = request.form['option_1']
    question.option_2 = request.form['option_2']
    question.option_3 = request.form['option_3']
    question.option_4 = request.form['option_4']
    question.correct_option = int(request.form['correct_option'])

    db.session.commit()
    flash('Question updated successfully!', 'success')

    # ✅ Redirect back to manage questions
    return redirect(url_for('manage_questions', quiz_id=question.quiz_id))

# Delete a question
@app.route('/admin/questions/delete/<int:question_id>', methods=['POST'])
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('manage_questions', quiz_id=quiz_id))

@app.route('/admin/summary')
def admin_summary():
    search_query = request.args.get('search', '').strip()

    # Fetch users based on search criteria, excluding admins
    users = User.query.filter(
        (User.role == "user") & 
        ((User.full_name.ilike(f'%{search_query}%')) | (User.email.ilike(f'%{search_query}%')))
    ).all()

    user_data = []
    for user in users:
        total_attempts = len(user.scores)  # Using 'scores' instead of 'quiz_attempts'
        total_score = sum(attempt.score for attempt in user.scores if attempt.score is not None)

        # Calculate average score safely
        avg_score = round(total_score / total_attempts, 2) if total_attempts else 0

        user_data.append({
            "id": user.id,
            "name": user.full_name,
            "email": user.email,
            "total_attempts": total_attempts,
            "avg_score": avg_score
        })

    return render_template('ad_summary.html', users=user_data, search_query=search_query)


#===========================================================================================================================================

#User side Routes

#✅ Ensures user is logged in
# ✅ Checks if the user role is "user"
# ✅ Fetches all available quizzes
# ✅ Gets previous quiz attempts of the user
# ✅ Prepares data for a performance chart (if needed) # Import necessary models

@app.route('/ud')
def ud():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))  # Ensure user is logged in

    user = User.query.get(user_id)

    # Calculate Total Score
    total_score = db.session.query(db.func.sum(Score.score)).filter(Score.user_id == user_id).scalar() or 0

    # Count Total Quiz Attempts
    total_attempts = Score.query.filter_by(user_id=user_id).count()

    # Fetch Last 5 Quiz Attempts (Recent Quiz History)
    quiz_history = Score.query.filter_by(user_id=user_id).order_by(Score.attempt_date.desc()).limit(5).all()

    # Fetch Available Quizzes
    available_quizzes = Quiz.query.all()  # You may need to filter based on conditions

    return render_template(
        'us_dash.html',
        user=user,
        total_score=total_score,
        total_attempts=total_attempts,
        quiz_history=quiz_history,
        available_quizzes=available_quizzes  # Add this to the template
    )


@app.route('/score')
def score():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user or user.role != 'user':
        return redirect(url_for('home'))

    # Fetch quiz attempts of the logged-in user
    quiz_attempts = Score.query.filter_by(user_id=user.id).order_by(Score.attempt_date.desc()).all()

    return render_template('us_scores.html', 
                           user=user, 
                           quiz_attempts=quiz_attempts)
@app.route('/user_summary/<int:user_id>')
def user_summary(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    total_quizzes = Score.query.filter_by(user_id=user_id).count()
    scores = Score.query.filter_by(user_id=user_id).all()

    best_score = max([score.score or 0 for score in scores], default=0)
    lowest_score = min([score.score or 0 for score in scores], default=0)

    chapter_attempts = {}
    quiz_names = []
    quiz_scores = []

    for score in scores:
        if score.quiz and score.quiz.chapter:
            chapter_name = score.quiz.chapter.name or "Unknown"
            quiz_names.append(chapter_name)  # Store chapter name instead of quiz name
        else:
            chapter_name = "Unknown"

        chapter_attempts[chapter_name] = chapter_attempts.get(chapter_name, 0) + 1
        quiz_scores.append(score.score or 0)

    most_attempted_chapter = max(chapter_attempts, key=chapter_attempts.get, default="None")

    return render_template("us_summary.html", user=user, total_quizzes=total_quizzes, 
                           best_score=best_score, lowest_score=lowest_score, 
                           most_attempted_chapter=most_attempted_chapter, 
                           quiz_names=quiz_names, quiz_scores=quiz_scores)






    
@app.route('/quiz/<int:quiz_id>')
def quiz(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('us_quiz.html', quiz=quiz, questions=questions)

@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
def submit_quiz(quiz_id):
    user_id = session.get('user_id')  # Ensure user is logged in

    if not user_id:
        flash("You must be logged in to submit the quiz.", "danger")
        return redirect(url_for('login'))

    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    total_questions = len(questions)
    correct_count = 0

    for question in questions:
        selected_option = request.form.get(f"q{question.id}")  # User's answer
        if selected_option and int(selected_option) == question.correct_option:
            correct_count += 1

    # Calculate final score
    final_score = (correct_count / total_questions) * 100 if total_questions > 0 else 0

    # Store in database
    new_score = Score(user_id=user_id, quiz_id=quiz_id, score=int(final_score))
    db.session.add(new_score)
    db.session.commit()

    flash(f"Quiz submitted! You scored {int(final_score)}%", "success")
    return redirect(url_for('score'))  


    



if __name__ == '__main__':
    app.run(debug=True)

