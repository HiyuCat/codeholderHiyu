import smtplib
import email
import os
import ssl
import imaplib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Gmail SMTP server settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Gmail IMAP server settings
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

# Gmail account credentials
GMAIL_ADDRESS = "test11037271@gmail.com"
GMAIL_PASSWORD = "****"

class Email:
    def __init__(self, sender, recipient, subject, body, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.body = body
        self.signature = signature

def sign_email(email_obj, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    message = f"Subject: {email_obj.subject}\n\n{email_obj.body}".encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def send_email_with_valid_signature(email_obj, private_key_path):
    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = email_obj.sender
    msg['To'] = email_obj.recipient
    msg['Subject'] = email_obj.subject
    msg.attach(MIMEText(email_obj.body, 'plain'))

    signature = sign_email(email_obj, private_key_path)

    signature_part = MIMEBase('application', 'pkcs7-signature')
    signature_part.set_payload(signature)
    encoders.encode_base64(signature_part)
    signature_part.add_header('Content-Disposition', 'attachment', filename='signature.p7s')
    msg.attach(signature_part)

    # Send the email
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
        server.send_message(msg)


def generate_fake_signature():
    fake_signature = b"This is a fake signature."
    return fake_signature

def send_email_with_invalid_signature(email_obj, private_key_path):
    msg = MIMEMultipart()
    msg['From'] = email_obj.sender
    msg['To'] = email_obj.recipient
    msg['Subject'] = email_obj.subject
    msg.attach(MIMEText(email_obj.body, 'plain'))

    fake_signature = generate_fake_signature()

    signature_part = MIMEBase('application', 'pkcs7-signature')
    signature_part.set_payload(fake_signature)
    encoders.encode_base64(signature_part)
    signature_part.add_header('Content-Disposition', 'attachment', filename='signature.p7s')
    msg.attach(signature_part)

    # Send the email
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
        server.send_message(msg)

def send_email_with_no_signature(email_obj):
    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = email_obj.sender
    msg['To'] = email_obj.recipient
    msg['Subject'] = email_obj.subject
    msg.attach(MIMEText(email_obj.body, 'plain'))

    # Send the email
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
        server.send_message(msg)

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def verify_email_signature(email_obj, public_key):
    if email_obj.signature is None:
        return False  
    message = f"Subject: {email_obj.subject}\n\n{email_obj.body}".encode()
    try:
        public_key.verify(
            email_obj.signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Signature verification successful
    except Exception:
        return False  # Signature verification failed

def receive_email():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
    mail.select('inbox')
    result, data = mail.search(None, 'UNSEEN')
    email_list = []
    for email_id in data[0].split():
        result, data = mail.fetch(email_id, '(RFC822)')
        raw_email = data[0][1]
        email_message = email.message_from_bytes(raw_email)
        sender = email.utils.parseaddr(email_message['From'])[1]
        subject = email_message['Subject']
        body = None
        signature = None
        for part in email_message.walk():
            if part is not None:
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                elif part.get_filename() == "signature.p7s":
                    # Read the signature bytes
                    signature = part.get_payload(decode=True)
        email_obj = Email(sender=sender, recipient=GMAIL_ADDRESS, subject=subject, body=body, signature=signature)
        email_list.append(email_obj)
    return email_list

def receive_email1():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
    mail.select('"[Gmail]/Sent Mail"')  
    result, data = mail.search(None, 'ALL')
    email_list = []
    for email_id in data[0].split()[-5:]:
        result, data = mail.fetch(email_id, '(RFC822)')
        raw_email = data[0][1]
        email_message = email.message_from_bytes(raw_email)
        sender = email.utils.parseaddr(email_message['From'])[1]
        subject = email_message['Subject']
        body = None
        signature = None
        for part in email_message.walk():
            if part is not None:
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                elif part.get_filename() == "signature.p7s":
                    # Read the signature bytes
                    signature = part.get_payload(decode=True)
        email_obj = Email(sender=sender, recipient=GMAIL_ADDRESS, subject=subject, body=body, signature=signature)
        email_list.append(email_obj)
    return email_list

if __name__ == "__main__":
    # Generate RSA key pair for email signing and verification
    private_key, public_key = generate_key_pair()

    # Save the private key to a file
    with open(os.path.join(os.getcwd(), "private_key.pem"), "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


    valid_email_with_valid_signature = Email(
        sender=GMAIL_ADDRESS,
        recipient="test11037271@gmail.com",
        subject="Email with Valid Signature",
        body="This is a email with a valid digital signature."
    )
    send_email_with_valid_signature(valid_email_with_valid_signature, os.path.join(os.getcwd(), "private_key.pem"))
    print("Sending email with valid signature")

    valid_email_with_invalid_signature = Email(
        sender=GMAIL_ADDRESS,
        recipient="test11037271@gmail.com",
        subject="Email with invalid Signature",
        body="This is a email with a valid digital signature."
    )
    send_email_with_invalid_signature(valid_email_with_invalid_signature, os.path.join(os.getcwd(), "private_key.pem"))
    print("Sending valid email with invalid signature")


    valid_email_with_no_signature = Email(
        sender=GMAIL_ADDRESS,
        recipient="test11037271@gmail.com",
        subject="Email with no Signature",
        body="This is a email with no digital signature."
    )
    send_email_with_no_signature(valid_email_with_no_signature)
    print("Sending email with no signature")

    # Receive emails and verify their signatures
    received_emails = receive_email()
    for email_obj in received_emails:
        if verify_email_signature(email_obj, public_key):
            print(f"Email with subject '{email_obj.subject}' from {email_obj.sender} is valid.")
        else:
            if email_obj.signature is None:
                print(f"Email with subject '{email_obj.subject}' from {email_obj.sender} has no signature.")
            else:
                print(f"Email with subject '{email_obj.subject}' from {email_obj.sender} is invalid.")

    print('/////////////////////////////////////')
    print('newest 5 sended email')
    print('/////////////////////////////////////')

    received_emails = receive_email1()
    for email_obj in received_emails:
        if verify_email_signature(email_obj, public_key):
            print(f"Email with subject '{email_obj.subject}' from {email_obj.sender} is valid.")
        else:
            if email_obj.signature is None:
                print(f"Email with subject '{email_obj.subject}' from {email_obj.sender} has no signature.")
            else:
                print(f"Email with subject '{email_obj.subject}' from {email_obj.sender} is invalid.")
