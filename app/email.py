from . import mail
from flask_mail import Message
from flask import render_template, current_app
# 异步发送电子邮件
from threading import Thread

# 异步发送电子邮件
def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

# 电子邮件支持
def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object()
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
                  sender=current_app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    #mail.send(msg)
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr
