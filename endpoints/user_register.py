from app import app
from flask import jsonify, request
from helpers.dbhelpers import *
import bcrypt
import uuid


# Bcrypt password encryption handling

def encrypt_password(password):
    salt = bcrypt.gensalt(rounds=5)
    hash_result = bcrypt.hashpw(password.encode(), salt)
    print(hash_result)
    decrypted_password = hash_result.decode()
    return decrypted_password

# TODO client info UPDATE and account delete
# Response Codes: 
#   1. 200 = Success client creation
#   2. 204 = success with No Content, which would be if nothing was edited in the user profile

# Error Codes: 
#   1. 401 = Access Denied becuase of lack of valid session token
#   2. 422 = Unprocessable because of lacking required info from client 
#   3. 500 = Internal Server Error

# Get User info

@app.get('/api/user')
def get_user_info():
    params = request.args
    # Check for valid session token
    session_token = params.get('sessionToken')
    if not session_token:   # If no session found then return error
        return jsonify("Session token not found!"), 401
    # If valid token then retrieve user info 
    user_info = run_query("SELECT * FROM user LEFT JOIN user_session ON user_session.user_id=user.id WHERE user_session.token=?",[session_token])
    if user_info is not None:
        return jsonify("User not found")
    else:    
        resp = []
        for item in user_info:
            user = {}
            user['userId'] = item[0]
            user['email'] = item[1]
            user['username'] = item[2]
            user['firstName'] = item[4]
            user['lastName'] = item[5]
            user['createdAt'] = item[6]
            user['pictureUrl'] = item[7]
            resp.append(user)
        return jsonify(resp)
    
        


@app.post('/api/user')
def user_register():
    data = request.json
    email = data.get('email')
    username = data.get('username')
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    password_input = data.get('password')
    password = encrypt_password(password_input)
    picture_url = data.get('pictureUrl')
    if not email:
        return jsonify("Email required"), 422
    if not username:
        return jsonify("Username required"), 422
    if not first_name:
        return jsonify("First Name required"), 422
    if not last_name:
        return jsonify("Last name required"), 422
    if not password_input:
        return jsonify("Password required"), 422
    run_query("INSERT INTO user (email, username, password, first_name, last_name, picture_url) VALUES (?,?,?,?,?,?)", [email, username, password, first_name, last_name, picture_url])
    user_data = run_query("SELECT * FROM user WHERE username=?", [username])
    session_token = str(uuid.uuid4().hex)
    user_id = user_data[0][0]
    run_query("INSERT INTO user_session (token,user_id) VALUES (?,?)", [session_token, user_id])
    if user_data is None:
        return jsonify("No session found")
    else:    
        resp = []
        for item in user_data:
            user = {}
            user['userId'] = item[0]
            user['email'] = item[1]
            user['username'] = item[2]
            user['firstName'] = item[4]
            user['lastName'] = item[5]
            user['createdAt'] = item[6]
            user['pictureUrl'] = item[7]
            resp.append(user)
        return jsonify(resp)


@app.patch('/api/user')
def edit_profile():
    # GET params for session check
    params = request.args
    session_token = params.get('sessionToken')
    if not session_token:
        return jsonify("Session token not found!")
    user_info = run_query("SELECT * FROM user JOIN user_session ON user_session.user_id=user.id WHERE token=?",[session_token])
    if user_info is not None:
        user_id = user_info[0][0]
        data = request.json
        build_statement = ""
        # string join
        build_vals = []
        if data.get('username'):
            new_username = data.get('username')
            build_vals.append(new_username)
            build_statement+="username=?"
        else:
            pass
        if data.get('password'):
            new_password_input = data.get('password')
            new_password = encrypt_password(new_password_input)
            build_vals.append(new_password)
            if ("username" in build_statement):
                build_statement+=",password=?"
            else:
                build_statement+="password=?"
        else:
            pass
        if data.get('firstName'):
            new_first_name = data.get('firstName')
            build_vals.append(new_first_name)
            if ("username" in build_statement) or ("password" in build_statement):
                build_statement+=",first_name=?"
            else:
                build_statement+="first_name=?"
        else:
            pass
        if data.get('lastName'):
            new_last_name = data.get('lastName')
            build_vals.append(new_last_name)
            if ("username" in build_statement) or ("password" in build_statement) or ("first_name" in build_statement):
                build_statement+=",last_name=?"
            else:
                build_statement+="last_name=?"
        else:
            pass
        if data.get('pictureUrl'):
            new_picture_url = data.get('pictureUrl')
            build_vals.append(new_picture_url)
            if ("username" in build_statement) or ("password" in build_statement) or ("first_name" in build_statement) or ("last_name" in build_statement):
                build_statement+=",picture_url=?"
            else:
                build_statement+="picture_url=?"
        else:
            pass
        build_vals.append(user_id)
        statement = str(build_statement)
        run_query("UPDATE user SET "+statement+" WHERE id=?", build_vals)
        # Create error(500) for the server time out, or another server issue during the update process
        return jsonify("Your info was successfully edited"), 204
    else:
        return jsonify("Session not found"), 500

@app.delete('/api/user')
def delete_account():
    params = request.args
    session_token = params.get('sessionToken')
    if not session_token:
        return jsonify("Session token not found!"), 401
    session = run_query("SELECT * FROM user_session WHERE token=?",[session_token])
    if session is not None:
        user_id = session[0][3]
        run_query("DELETE FROM user_session WHERE token=?",[session_token])
        run_query("DELETE FROM user WHERE id=?",[user_id])
        return jsonify("Account deleted"), 204
    else:
        return jsonify("You must be logged in to delete your account"), 500