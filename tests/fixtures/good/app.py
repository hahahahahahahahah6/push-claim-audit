from firebase_admin.messaging import Message, send
m = Message(token="fixture")
send(m)
