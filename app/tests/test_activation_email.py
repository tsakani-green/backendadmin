import asyncio
import smtplib
from email.message import EmailMessage
import pytest

from app.api import auth


class DummySMTP:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.logged_in = False
        self.sent_messages = []

    def starttls(self):
        return True

    def login(self, username, password):
        self.logged_in = True

    def send_message(self, msg: EmailMessage):
        self.sent_messages.append(msg)

    def quit(self):
        return True


@pytest.mark.asyncio
async def test_send_activation_email_monkeypatch(monkeypatch):
    sent = {}

    def fake_smtp(host, port):
        sent['smtp'] = DummySMTP(host, port)
        return sent['smtp']

    monkeypatch.setattr(smtplib, 'SMTP', fake_smtp)

    to_email = 'e2e@test.example'
    user_name = 'E2E Tester'
    activation_link = 'https://example.test/activate?token=tok'

    # call the async send_activation_email
    await auth.send_activation_email(to_email, user_name, activation_link)

    smtp = sent.get('smtp')
    assert smtp is not None, 'SMTP should be constructed'
    assert smtp.logged_in is True
    assert len(smtp.sent_messages) == 1
    msg = smtp.sent_messages[0]
    assert to_email in msg['To']
    payload = msg.get_payload()[0].get_payload()
    assert activation_link in payload
