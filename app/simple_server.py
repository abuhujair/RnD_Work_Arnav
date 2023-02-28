'''
ENV FLASK_APP=monitor_server.py
CMD flask run -h 0.0.0 -p 7000
'''
from flask import Flask
app = Flask(__name__)

#  just a dummy server
@app.route("/")
def hello():
    return "Hello World!"

