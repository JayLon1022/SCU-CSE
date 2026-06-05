import os
import re
import logging
import secrets
import string
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from captcha.image import ImageCaptcha
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
import json

# 加载环境内容
def load_env_file(filepath):
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()
# 加载 .env 文件
load_env_file('.env')

# Flask 应用初始化
app = Flask(__name__)

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# 设置 werkzeug 日志级别为 INFO
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)

# 配置
class Config:
    SECRET_KEY = os.urandom(32)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///secure_auth.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.qq.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')


# 应用配置
app.config.from_object(Config)
app.config['SECRET_KEY'] = Config.SECRET_KEY

# 扩展初始化
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
csrf = CSRFProtect(app)

# 请求频率限制
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per day", "30 per hour"]
)
limiter.init_app(app)


# 用户模型
class User(UserMixin, db.Model):
    # 用户基本信息字段
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=False)

    # 安全相关字段
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, nullable=True)
    lock_until = db.Column(db.DateTime, nullable=True)

    # PKI相关字段
    public_key = db.Column(db.Text, nullable=True)

    # 验证码相关字段
    email_code = db.Column(db.String(6), nullable=True)
    email_code_created_at = db.Column(db.DateTime, nullable=True)
    otp_code = db.Column(db.String(6), nullable=True)
    otp_code_created_at = db.Column(db.DateTime, nullable=True)

    # 日志记录相关字段
    action_logs = db.Column(db.Text, nullable=True)

    def set_password(self, password):
        """安全设置密码"""
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )

    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)

    def is_password_valid(self, password):
        """
        密码复杂度验证
        1. 最少8个字符
        2. 包含大小写字母
        3. 包含数字
        4. 包含特殊字符
        """
        if len(password) < 8:
            return False

        has_upper = False
        has_lower = False
        has_digit = False
        has_special = False

        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        for char in password:
            if char.isupper():
                has_upper = True
            elif char.islower():
                has_lower = True
            elif char.isdigit():
                has_digit = True
            elif char in special_chars:
                has_special = True

        return has_upper and has_lower and has_digit and has_special

    def increment_login_attempts(self):
        """登录失败处理"""
        now = datetime.utcnow()

        # 如果上次尝试超过1小时，重置计数
        if (not self.last_login_attempt or
                (now - self.last_login_attempt).total_seconds() > 3600):
            self.login_attempts = 1
        else:
            self.login_attempts += 1

        self.last_login_attempt = now

        # 5次失败锁定15分钟
        if self.login_attempts >= 5:
            self.lock_until = now + timedelta(minutes=15)

        db.session.commit()

    def is_locked(self):
        """检查账户是否被锁定"""
        if not self.lock_until:
            return False

        return datetime.utcnow() < self.lock_until


# 表单类
class RegisterForm(FlaskForm):
    username = StringField('用户名', validators=[
        InputRequired(),
        Length(min=4, max=50, message='用户名长度必须在4-50个字符之间')
    ])
    email = StringField('邮箱', validators=[
        InputRequired(),
        Email(message='请输入有效的邮箱地址')
    ])
    password = PasswordField('密码', validators=[
        InputRequired(),
        Length(min=8, max=50, message='密码长度必须至少8个字符')
    ])
    email_code = StringField('邮箱验证码', validators=[
        InputRequired(),
    ])
    submit = SubmitField('注册')

class RegisterVerifyForm(FlaskForm):
    email = StringField('邮箱', validators=[
        InputRequired(),
        Email(message='请输入有效的邮箱地址')
    ])
    submit = SubmitField('验证')

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[
        InputRequired(),
        Length(min=4, max=50)
    ])
    password = PasswordField('密码', validators=[
        InputRequired(),
        Length(min=8, max=50)
    ])

    captcha = StringField('验证码', validators=[
        InputRequired()
    ])

    submit = SubmitField('登录')

class LoginVerifyForm(FlaskForm):
    otp_code = StringField('OTP验证码', validators=[
        InputRequired(),
        Length(min=4, max=6)
    ])
    submit = SubmitField('验证')

class LogoutForm(FlaskForm):
    submit = SubmitField('下线')


# 登录工具函数
def generate_verification_code(length=6):
    """生成验证码"""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def send_verification_email(email, code):
    """发送验证邮件"""
    try:
        msg = Message(
            '身份验证验证码',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'您的验证码是：{code}，5分钟内有效'
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"邮件发送失败: {e}")
        return False

def generate_captcha():
    """生成图形验证码"""
    image = ImageCaptcha()
    captcha_text = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    image_data = image.generate(captcha_text)
    image_bytes = image_data.read()
    encoded_image = base64.b64encode(image_bytes).decode('utf-8')
    return captcha_text.lower(), f"data:image/png;base64,{encoded_image}"

def register_verification(user, code):
    """注册验证"""
    if code != user.email_code:
        return False
    else:
        return True

def login_verification(user, code):
    """登录验证"""
    if code != user.otp_code:
        return False
    else:
        return True

# 安全性函数
def generate_ecc_key():
    """生成ECC密钥对"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def sign_operation(private_key, data):
    """对操作进行数字签名"""
    signature = private_key.sign(
        data.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(public_key, data, signature):
    """验证操作签名"""
    try:
        public_key.verify(
            signature,
            data.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def log_user_action(user_id, action, message):
    """记录日志"""
    timestamp = datetime.utcnow().isoformat()
    data = json.dumps({"user_id": user_id, "action": action, "timestamp": timestamp, "message": message})
    log_entry = {
        "data": data,
    }
    with open('user_logs.json', 'a') as log_file:
        log_file.write(json.dumps(log_entry) + '\n')


# 路由
@app.route('/register_verify', methods=['GET', 'POST'])
def register_verify():

    form = RegisterVerifyForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            raise ValidationError('该邮箱已被注册')

        # 创建新用户
        new_user = User()
        new_user.email = form.email.data
        # 生成邮箱验证码
        email_code = generate_verification_code()
        new_user.email_code = email_code
        new_user.email_code_created_at = datetime.utcnow()

        db.session.add(new_user)
        db.session.commit()

        # 发送验证邮件
        if send_verification_email(new_user.email, email_code):
            session['register_email'] = new_user.email
            flash('发送成功，请查收验证码')
            return redirect(url_for('register'))
        else:
            flash('邮件发送失败，请稍后重试')

    return render_template('register_verify.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()

    email = session.get('register_email')
    if not email:
        flash('会话已过期，请重新注册')
        return render_template('register.html', form=form)

    if form.validate_on_submit():
        # 密码复杂度检查
        if not User().is_password_valid(form.password.data):
            flash('密码过于简单')
            return render_template('register.html', form=form)

        # 邮箱一致性检查
        if form.email.data != email:
            flash('两次邮箱输入不一致')
            return render_template('register.html', form=form)

        # 用户重复性检查
        if User.query.filter_by(username=form.username.data).first():
            user = User.query.filter_by(username=form.username.data).first()
            log_user_action(user.id, 'Register', "Register repeatedly")
            flash('该用户名已被注册')
            return render_template('register.html', form=form)

        user = User.query.filter_by(email=email).first()

        # 生成ECC密钥对
        private_key = generate_ecc_key()
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        user.public_key = pem.decode('utf-8')
        user.set_password(form.password.data)
        user.username = form.username.data

        email_code = form.email_code.data

        # 验证码有效期检查
        if (register_verification(user,email_code) and
                user.email_code_created_at and
                (datetime.utcnow() - user.email_code_created_at).total_seconds() < 300):

            user.email_code = None
            user.email_code_created_at = None
            db.session.commit()
            flash('验证成功，请登录')
            log_user_action(user.id, 'Register', "Register_success")
            return redirect(url_for('login'))
        else:
            log_user_action(user.id, 'Register', "Wrong email_code")
            flash('验证码错误或已过期')
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # 验证图形验证码
        submitted_captcha = form.captcha.data.lower()
        stored_captcha = session.get('captcha', '').lower()
        if submitted_captcha != stored_captcha:
            flash('验证码错误')
            return render_template('login.html', form=form)

        # 查找用户
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            log_user_action(user.id, 'Login', "Repeat Username")
            flash('用户名不存在')
            return render_template('login.html', form=form)

        if user.is_active:
            log_user_action(user.id, 'Login', "Login repeatedly")
            flash('用户已登录')
            return render_template('login.html', form=form)
        # 检查账户锁定
        if user.is_locked():
            remaining_time = int((user.lock_until - datetime.utcnow()).total_seconds() / 60)
            flash(f'账户已锁定，请{remaining_time}分钟后重试')
            return render_template('login.html', form=form)

        # 验证密码
        if user.check_password(form.password.data):
            # 重置登录尝试
            user.login_attempts = 0
            user.last_login_attempt = None
            db.session.commit()

            # 生成OTP
            otp_code = generate_verification_code()
            user.otp_code = otp_code
            user.otp_code_created_at = datetime.utcnow()
            db.session.commit()

            # 发送验证码
            if send_verification_email(user.email, otp_code):
                session['login_username'] = user.username
                flash('验证码发送成功')
                return redirect(url_for('login_verify'))
            else:
                flash('验证码发送失败')
        else:
            # 记录登录失败
            user.increment_login_attempts()
            log_user_action(user.id, 'Login', "Wrong password")
            flash('密码错误')
            return render_template('login.html', form=form)


    else:
        captcha_text, captcha_image = generate_captcha()
        session['captcha'] = captcha_text
        print(captcha_text)

    return render_template('login.html', form=form, captcha_image=captcha_image)


@app.route('/login_verify', methods=['GET', 'POST'])
def login_verify():
    form = LoginVerifyForm()

    if form.validate_on_submit():
        username = session.get('login_username')
        if not username:
            flash('会话已过期')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        # OTP检查
        if (login_verification(user, form.otp_code.data) and
                user.otp_code_created_at and
                (datetime.utcnow() - user.otp_code_created_at).total_seconds() < 300):

            # 记录日志
            log_user_action(user.id, 'login', "login_success")

            # 更新用户状态
            user.is_active = True  # 根据系统需求进行更改
            user.otp_code = None
            user.otp_code_created_at = None
            db.session.commit()

            login_user(user)
            flash('登录成功')
            return redirect(url_for('dashboard'))
        else:
            log_user_action(user.id, 'Login', "Wrong OTP")
            flash('验证码错误或已过期')

    return render_template('login_verify.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = LogoutForm()
    username = session.get('login_username')
    if not username:
        flash('会话已过期')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if form.validate_on_submit():
        log_user_action(user.id, 'logout', "logout_success")
        logout_user()
        user.is_active = False
        db.session.commit()
        flash('您已成功退出')
        return redirect(url_for('login'))

    return render_template('dashboard.html', form=form)



# 用户加载器
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)