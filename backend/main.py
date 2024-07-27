
from flask import Flask, request, jsonify, session
import json
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from config import ApplicationConfig
from models import db, User
from flask_session import Session
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, unset_jwt_cookies,jwt_required, JWTManager
from datetime import timedelta, datetime, timezone


app = Flask(__name__)
app.config.from_object(ApplicationConfig)

bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True) 
server_session = Session(app)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route("/signup", methods=["POST"])
def signup():
    email = request.json["email"]
    username = request.json["username"]
    password = request.json["password"]

    user_exists = User.query.filter_by(email = email).first() is not None

    if user_exists:
        return jsonify({"error": "User already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(password)
    new_user = User( email = email, username = username, password = hashed_password)
    db.session.add(new_user)
    db.session.commit()

    #session["user_id"] = new_user.id  

    return jsonify({
        "id": new_user.id,
        "email": new_user.email
    })


@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    email = request.json["email"]
    password = request.json["password"]

    user = User.query.filter_by(email = email).first()
    username = User.query.filter_by(username = username).first()
    

    if user is None:
        return jsonify({"error": "Unauthorized Access"}), 401
  
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401  
    
    #session["user_id"] = user.id
    access_token = create_access_token(identity = email)

    return jsonify({
        "email" : user.email,
        "access_token": access_token
    })

@app.after_request
def refresh_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestap = datetime.timestamp(now + timedelta(minutes = 30))
        if target_timestap > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity)
            data = response.get_json()
            if type(data) is dict:
                data["access_token"] = access_token
                response.data = json.dumps(data)
        return response
    except (RuntimeError, KeyError):
        return response


@app.route("/logout", methods =["POST"])
def logout_user():
    response = jsonify({"msg": "lougout successful"})
    unset_jwt_cookies(response)
    return response

@app.route('/account/<getemail>')
@jwt_required()
def my_account(getemail):
    print(getemail)
    if not getemail:
        return jsonify({"error": "Unauthorized access"}), 401
    
    user = User.query.filter_by(email =getemail).first()

    response_body = {
        "id": user.id,
        "email": user.email,
        "username": user.username
    }

    return response_body


if __name__ == "__main__":
    app.run(debug=True)