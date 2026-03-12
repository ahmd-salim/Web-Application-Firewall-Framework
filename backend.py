from flask import Flask, request

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    return {
        "message": "Backend received request",
        "args": request.args,
        "method": request.method
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    return {
        "message": "Login endpoint reached",
        "data": request.args
    }


if __name__ == "__main__":
    app.run(port=8001)
