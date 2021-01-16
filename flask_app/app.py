from flask import Flask, render_template, url_for, request
from dbalchemy import db, app, User, Account
import hashlib
import os


salt=b'qqq'
u_id = ""


@app.route('/')
def main():
    return render_template("index.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    users_pass = str(get_password(username))
    pass_en = bytes(password, 'utf-8')

    input_pass = hashlib.pbkdf2_hmac('sha256', pass_en, salt, 100000)

    u_id = str(username)
    
    if users_pass == str(input_pass):
        services_l = Account.query.filter_by(username = u_id).all()
        return render_template("services.html", services_l = services_l)
    else:
        return "Your username or password might be incorrect."


@app.route('/add_user', methods=['POST', 'GET'])
def add_user():
    return render_template("up_users.html")


@app.route('/update_users', methods=['POST'])
def update_users():
    username = request.form.get("new_user")
    password = request.form.get("new_pass")

    if verify_strong_password(password) == False:
        return render_template("up_users.html", content=f"Your password is not strong enough. Make sure it contains 8 symbols, letters both in upper case and lower case, as well as at least one digit. ")
    
    pass_en = bytes(password, 'utf-8')

    new_h = hashlib.pbkdf2_hmac('sha256', pass_en, salt, 100000)

    us = User(username=username, password=str(new_h))
            
    db.session.add(us)
    db.session.commit()
    return render_template("index.html")


@app.route('/form_add_service', methods=['POST', 'GET'])
def form_add_service():
    return render_template("service_form.html")


@app.route('/update_account', methods=['POST'])
def update_account():
    servicename = request.form.get("new_service")
    password = request.form.get("new_password")
    masterp = request.form.get("masterpassword")

    if verify_strong_password(password) == False:
        return render_template("services.html", content=f"Your password was not secure enough..")
    
    pass_en = bytes(password, 'utf-8')
    masterp_en = bytes(masterp, 'utf-8')
    new_h = hashlib.pbkdf2_hmac('sha256', pass_en, masterp_en, 100000)

    ac = Account(username=u_id, service = servicename, password=new_h)
            
    db.session.add(ac)
    db.session.commit()
    
    services_l = Account.query.filter_by(username = u_id).all()
    return render_template("services.html", services_l = services_l)


@app.route('/form_get_service', methods=['POST', 'GET'])
def form_get_service():
    return render_template("service_get_form.html")


def verify_strong_password(password):

    forbidden = ["script", "--", "/*", "SELECT", "DELETE", "INSERT", "UPDATE"]
    for x in forbidden:
        if password.find(x) == True:
            return False

    rules = [lambda password: any(x.isupper() for x in password),
            lambda password: any(x.islower() for x in password),
            lambda password: any(x.isdigit() for x in password),
            lambda password: len(password) >= 4]
    if all(rule(password) for rule in rules):
        return True
    else:
        return False


def get_password(user):
    obj = User.query.filter_by(username = user).first()
    if isinstance(obj, User):
        return obj.password
    else:
        return render_template("temp.html", content=f"Can't return password for some reason."), 403
    
    
def get_id(user):
    obj = User.query.filter_by(username = user).first()
    if isinstance(obj, User):
        return obj.id_user
    else:
        return render_template("temp.html", content=f"Can't return user's ID."), 403


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')