from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart

class EmailClient():
    def __init__(self, smtp_server='127.0.0.1', smtp_port=1025, **kwargs):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def send_email(self, receivers, sender, content, subject, text_subtype='html', attachments=None, **kwargs):
        '''
        Takes in the sender and an array of recievers and then sends the given message body. Messages can be HTML formatted.
        text_subtype can be: plain, html, xml
        '''
        
        if isinstance(receivers, str):
            receivers = [receivers]
        
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ','.join(receivers)
        body = MIMEText(content, text_subtype)
        msg.attach(body)

        # attach attachments
        for path, name in attachments or []:
            with open(path, 'rb') as f:
                attachment = MIMEApplication(f.read(), Name=name)
                attachment['Content-Disposition'] = f'attachment; filename="{name}"'
                msg.attach(attachment)

        smtpObj = SMTP(self.smtp_server, self.smtp_port)
        smtpObj.sendmail(sender, receivers, msg.as_string())
