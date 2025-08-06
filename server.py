from flask import Flask, redirect, Response

app = Flask(__name__)

@app.route('/old-biometric-endpoint')
def old_endpoint():
    # Simulate a redirection
    return redirect("/new-biometric-endpoint", code=302)

@app.route('/new-biometric-endpoint')
def new_endpoint():
    # Simulate success
    return Response("Biometric endpoint reached successfully.", status=200)

if __name__ == '__main__':
    app.run(port=5000)  # Make sure the port matches your client
