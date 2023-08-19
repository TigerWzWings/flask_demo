from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello_world():
	return 'My first demo to learn Flask.Hello_wolrd!'
