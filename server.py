from flask import Flask
app = Flask(__name__)

request_count = 0

@app.route('/')
def hello():
    global request_count
    request_count += 1
    return f"Hello from server! Request count: {request_count}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)