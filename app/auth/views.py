from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user
from . import auth
from ..models import User
from .. import db
from .forms import LoginForm, RegistrationForm, ResetPassword
# 退出路由
from flask_login import logout_user, login_required
# 发送确认邮件
from ..email import send_email
# 确认用户的账户
from flask_login import current_user

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

# 用户注册路由
# 发送确认邮件
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                   'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


# 确认用户的账户
@auth.route('/confirm/<token>')
def confirm(token):
    if current_user.is_authenticated:
        if current_user.confirmed:
            return redirect(url_for('main.index'))
        if current_user.confirm(token):
            flash('You have confirmed your account.Thanks!')
        else:
            flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

# 在before_app_request处理程序中过滤未确认的账户, 更新已登录用户的访问时间
@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
            and request.endpoint[:5] != 'auth.' \
            and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

# 重新发送账户确认邮件
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
               'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))

# 修改密码
@auth.route('/resetpassword', methods=['GET', 'POST'])
def reset_password():
    form = ResetPassword()
    if current_user.is_authenticated and form.validate_on_submit() and current_user.verify_password(form.old_password.data):
        current_user.password = form.new_password.data
        db.session.add(current_user)
        flash('Your password has been reseted.')
        return redirect(url_for('auth.login'))
    return render_template('auth/resetpassword.html', form=form)