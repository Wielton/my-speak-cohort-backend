from app import app
from flask import jsonify, request
from helpers.dbhelpers import *
import bcrypt
import uuid



# User login/logout endpoint

@app.post('/api/user-login')
def user_login():
    data = request.json
    email_input = data.get('email')
    password_input = data.get('password')
    if not email_input:
        return jsonify("Email required"), 422
    if not password_input:
        return jsonify("Password required"), 422
    user_info = run_query("SELECT * FROM user WHERE email=?", [email_input])
    if user_info is not None:
        user_password = user_info[0][3]
        if not bcrypt.checkpw(password_input.encode(), user_password.encode()):
            return jsonify("Error"),401
        user_id = user_info[0][0]
        session_token = str(uuid.uuid4().hex)
        logged_in = run_query("SELECT * FROM user_session WHERE user_id=?",[user_id])
        if not logged_in:
            run_query("INSERT INTO client_session (token,client_id) VALUES (?,?)", [session_token,user_id])
        elif user_id == logged_in[0][3]:
            # I could UPDATE here but I chose to delete then create a new session instance as I figured this is a better thing to do because of token lifecycles and other errors that could occur from just updating one column
            run_query("DELETE FROM user_session WHERE user_id=?",[user_id])
            run_query("INSERT INTO user_session (token,user_id) VALUES (?,?)", [session_token,user_id])
        return jsonify("User signed in"),201
    else:
        return jsonify("Email not found.  PLease try again"), 500


@app.delete('/api/user-login')
def user_logout():
    params = request.args
    session_token = params.get('sessionToken')
    session = run_query("SELECT * FROM client_session WHERE token=?",[session_token])
    if session is not None:
        run_query("DELETE FROM user_session WHERE token=?",[session_token])
        return jsonify("User logged out"),204
    else:
        return jsonify("You must be logged in to delete your account."), 500