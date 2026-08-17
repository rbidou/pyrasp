from flask import Flask, request, jsonify
import os
import signal

app = Flask(__name__)

try:
    from pyrasp.pyrasp import FlaskRASP

    FlaskRASP(app, conf="rasp.json")
    print("RASP mode enabled")
except ImportError:
    print("No RASP mode")


@app.route("/", methods=["GET"])
def echo():
    """
    Returns the received input.
    Examples:
      GET /?msg=hello
      response {"msg": "hello"}
    """
    msg = request.args.get("msg", "")

    # Stop service if "STOP" is received
    if str(msg).upper() == "STOP":
        os.kill(os.getpid(), signal.SIGTERM)

    return jsonify({"received": msg})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
