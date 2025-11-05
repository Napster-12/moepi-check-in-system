from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
import calendar

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from flask import jsonify, request

from datetime import datetime
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace_this_with_a_strong_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'moepi.sql')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------------------- Flask-Mail configuration --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'codnellsmall@gmail.com'
app.config['MAIL_PASSWORD'] = 'mrmxmmomvhvfqoee'
app.config['MAIL_DEFAULT_SENDER'] = 'codnellsmall@gmail.com'
mail = Mail(app)

# Token serializer
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -------------------- Database --------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class CheckIn(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    slot = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date = db.Column(db.Date, nullable=False)
    comment = db.Column(db.String(255), nullable=True)

    user = db.relationship('User', backref='checkins')



with app.app_context():
    db.create_all()

    # ---------- Create default admin ----------
    admin_email = "support@tekete.co.za"
    admin_password = "Admin12"
    admin_name = "System Administrator"

    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin = User(
            fullname=admin_name,
            email=admin_email,
            is_admin=True
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print(f"[INFO] Default admin account created: {admin_email} / {admin_password}")
    else:
        print("[INFO] Admin account already exists.")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Constants --------------------
CHECKIN_SLOTS = ["00:30", "00:36", "00:31"]

# -------------------- Routes --------------------
@app.route('/')
def home():
    return render_template('home.html')

# -------------------- Registration --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email'].strip().lower()
        password = request.form['password']

        # ✅ Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with that email already exists.', 'danger')
            return redirect(url_for('register'))

        # Otherwise, create new user
        user = User(fullname=fullname, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# -------------------- Login --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash('Logged in successfully.', 'success')
        return redirect(url_for('admin_dashboard') if user.is_admin else url_for('dashboard'))

    return render_template('login.html')

# -------------------- Logout --------------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))

# -------------------- Forgot Password --------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message('Password Reset Request', recipients=[user.email])
            msg.body = f"Hi {user.fullname},\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you didn't request this, ignore this email."
            mail.send(msg)

        flash('If this email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

# -------------------- Reset Password --------------------
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash('Your password has been reset. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# -------------------- Employee Dashboard --------------------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    now = datetime.now()
    slot_states = {}
    for slot in CHECKIN_SLOTS:
        already = CheckIn.query.filter_by(
            user_id=current_user.id, slot=slot, date=now.date()
        ).first()
        slot_states[slot] = {'already': bool(already), 'comment': already.comment if already else None}

    recent = CheckIn.query.filter_by(user_id=current_user.id)\
        .order_by(CheckIn.timestamp.desc())\
        .limit(20).all()

    return render_template('dashboard.html', slot_states=slot_states, now=now, recent=recent)

# -------------------- Check-in --------------------
@app.route('/checkin/<slot>', methods=['POST'])
@login_required
def checkin(slot):
    if slot not in CHECKIN_SLOTS:
        flash('Invalid check-in slot.', 'danger')
        return redirect(url_for('dashboard'))

    comment = request.form.get('comment', '').strip()
    now = datetime.now()

    # Convert slot (e.g. "11:00") to today's datetime
    slot_time = datetime.strptime(slot, "%H:%M").time()
    slot_datetime = datetime.combine(now.date(), slot_time)

    # Define the 10-minute valid window
    start_time = slot_datetime
    end_time = slot_datetime + timedelta(minutes=10)

    # Check if current time is within the window
    if not (start_time <= now <= end_time):
        flash(f"⏰ Check-in for {slot} is only allowed between {slot} and {end_time.strftime('%H:%M')}.", "danger")
        return redirect(url_for('dashboard'))

    # Prevent duplicate check-ins
    existing = CheckIn.query.filter_by(
        user_id=current_user.id, slot=slot, date=now.date()
    ).first()

    if existing:
        flash(f"You already checked in for {slot} today.", 'warning')
        return redirect(url_for('dashboard'))

    # Record the check-in
    ci = CheckIn(
        user_id=current_user.id,
        slot=slot,
        timestamp=now,
        date=now.date(),
        comment=comment
    )
    db.session.add(ci)
    db.session.commit()

    flash(f"✅ Check-in for {slot} recorded successfully.", 'success')
    return redirect(url_for('dashboard'))


# -------------------- Admin Dashboard --------------------
# -------------------- Admin Dashboard --------------------
@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    # ---------------- Filters ----------------
    name_filter = request.args.get('name', '').strip()
    month_filter = request.args.get('month', '')
    year_filter = request.args.get('year', '')

    # ---------------- Query Employees ----------------
    employees = User.query.order_by(User.fullname.asc()).all()

    # ---------------- Query Check-ins ----------------
    query = CheckIn.query.join(User)

    if name_filter:
        query = query.filter(User.fullname.ilike(f"%{name_filter}%"))
    if month_filter:
        query = query.filter(db.extract('month', CheckIn.date) == int(month_filter))
    if year_filter:
        query = query.filter(db.extract('year', CheckIn.date) == int(year_filter))

    # ---------------- Pagination ----------------
    page = request.args.get('page', 1, type=int)
    pagination = query.order_by(CheckIn.date.desc(), CheckIn.timestamp.desc()).paginate(page=page, per_page=20)
    checkins = pagination.items

    # ---------------- Statistics ----------------
    total_checkins = query.count()
    overall_check = CheckIn.query.count()
    highest_checkin_employee = (
        db.session.query(User.fullname, db.func.count(CheckIn.id).label('total'))
        .join(CheckIn)
        .group_by(User.id)
        .order_by(db.desc('total'))
        .first()
    )
    earliest_checkin = db.session.query(CheckIn).order_by(CheckIn.timestamp.asc()).first()

    now = datetime.now()

    # ---------------- Chart Data: Check-ins by Month ----------------
    from sqlalchemy import func
    month_data = (
        db.session.query(func.strftime('%m', CheckIn.date).label('month'), func.count(CheckIn.id))
        .group_by('month')
        .order_by('month')
        .all()
    )
    month_labels = [datetime.strptime(m, '%m').strftime('%B') for m, _ in month_data]
    month_counts = [c for _, c in month_data]

    # ---------------- Chart Data: Check-ins by Employee ----------------
    employee_data = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .group_by(User.fullname)
        .order_by(User.fullname)
        .all()
    )
    employee_names = [e for e, _ in employee_data]
    employee_counts = [c for _, c in employee_data]

    # ---------------- Attendance Summary ----------------
    # Example: assume 22 working days in the current month
    all_days = 22
    unique_days = len(set([c.date for c in query.all()]))
    absent_days = max(0, all_days - unique_days)
    attendance_labels = ['Present Days', 'Absent Days']
    attendance_data = [unique_days, absent_days]

    # ---------------- Render Template ----------------
    return render_template(
        'admin_dashboard.html',
        checkins=checkins,
        pagination=pagination,
        total_checkins=total_checkins,
        overall_check=overall_check,
        highest_checkin_employee=highest_checkin_employee,
        earliest_checkin=earliest_checkin,
        employees=employees,
        name_filter=name_filter,
        month_filter=month_filter,
        year_filter=year_filter,
        now=now,
        # Chart data
        month_labels=month_labels,
        month_counts=month_counts,
        employee_names=employee_names,
        employee_counts=employee_counts,
        attendance_labels=attendance_labels,
        attendance_data=attendance_data
    )



@app.route('/admin/data')
@login_required
def admin_dashboard_data():
    if not current_user.is_admin:
        return jsonify({"error": "Access denied."})

    name_filter = request.args.get('name', '').strip()
    month_filter = request.args.get('month', '')
    year_filter = request.args.get('year', '')

    query = CheckIn.query.join(User)

    # --- Apply filters ---
    if name_filter:
        query = query.filter(User.fullname.ilike(f"%{name_filter}%"))
    if month_filter:
        query = query.filter(func.extract('month', CheckIn.date) == int(month_filter))
    if year_filter:
        query = query.filter(func.extract('year', CheckIn.date) == int(year_filter))

    # --- Total count ---
    total_checkins = query.count()

    # --- Earliest check-in ---
    earliest_checkin_obj = query.order_by(CheckIn.timestamp.asc()).first()
    earliest_checkin = (
        earliest_checkin_obj.timestamp.strftime("%Y-%m-%d %H:%M")
        if earliest_checkin_obj else "-"
    )

    # --- Most active employee ---
    most_active = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .group_by(User.id)
        .order_by(func.count(CheckIn.id).desc())
        .first()
    )
    most_active_employee = most_active[0] if most_active else "-"

    # --- Least active employee ---
    least_active = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .group_by(User.id)
        .order_by(func.count(CheckIn.id))
        .first()
    )
    least_active_employee = least_active[0] if least_active else "-"

    # --- Monthly check-ins ---
    month_labels = list(calendar.month_name)[1:]
    month_counts = [
        query.filter(func.extract('month', CheckIn.date) == i).count() for i in range(1, 13)
    ]

    # --- Check-ins by employee ---
    employees = (
        db.session.query(User.fullname, func.count(CheckIn.id))
        .join(CheckIn)
        .group_by(User.id)
        .all()
    )
    employee_names = [e[0] for e in employees]
    employee_counts = [e[1] for e in employees]

    # --- Build full check-in history (filtered) ---
    checkins = (
        query.with_entities(
            User.fullname.label('employee'),
            CheckIn.date,
            CheckIn.timestamp,
            CheckIn.comment
        )
        .order_by(CheckIn.date.desc(), CheckIn.timestamp.desc())
        .all()
    )

    # Convert to JSON-friendly structure
    checkin_list = [
        {
            "employee": c.employee,
            "date": c.date.strftime("%Y-%m-%d"),
            "time": c.timestamp.strftime("%H:%M:%S"),
            "comment": c.comment or ""
        }
        for c in checkins
    ]

    return jsonify({
        "total_checkins": total_checkins,
        "earliest_checkin": earliest_checkin,
        "most_active_employee": most_active_employee,
        "least_active_employee": least_active_employee,
        "month_labels": month_labels,
        "month_counts": month_counts,
        "employee_names": employee_names,
        "employee_counts": employee_counts,
        "checkins": checkin_list  # ✅ send full check-in history
    })


# -------------------- Run --------------------
if __name__ == '__main__':
    app.run(debug=True)
