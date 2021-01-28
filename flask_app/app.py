from flask import render_template, url_for, request, session
from dbalchemy import db, app, User, Account, PswReset, login_manager, csrf, talisman
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import time, os, uuid, sys
import base64, pbkdf2
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask_wtf.csrf import CSRFError, CSRFProtect


@app.route('/')
def main():
    return render_template("index.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    "".join(username.split())
    "".join(password.split())

    honey = check_on_honey(str(username))
    if isinstance(honey, str):
        return honey

    users_pass = str(get_password(username))
    try:
        u_id = get_current_id(str(username))
        user = User.query.filter_by(id_user = u_id).first()
        if user.attempts > 0:
            if check_password_hash(users_pass, str(password)) == True:
                login_user(user)
                user.attempts = 5
                db.session.commit()
                time.sleep(2)
                services_l = Account.query.filter_by(id_user = current_user.id_user).all()
                return render_template("services.html", services_l = services_l)
            else:
                time.sleep(2)
                user.attempts -= 1
                db.session.commit()
                return "Your username or password might be incorrect. Attempts left: " + str(user.attempts)
        else:
            user.attempts = 5
            db.session.commit()
            time.sleep(60)
            return render_template("index.html")
    except:
        time.sleep(2)
        return "This user does not exist. Try again"


        
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return render_template("index.html")


@app.route('/add_user', methods=['POST', 'GET'])
def add_user():
    return render_template("up_users.html")


@app.route('/update_users', methods=['POST'])
def update_users():
    username = request.form.get("new_user")
    password = request.form.get("new_pass")
    email = request.form.get("email")
    "".join(username.split())
    "".join(password.split())
    "".join(email.split())

    if verify_strong_password(password) == False:
        return render_template("up_users.html", content=f"Your password is not strong enough. Make sure it contains 8 symbols, letters both in upper case and lower case, as well as at least one digit. ")
    
    pass_en = bytes(password, 'utf-8')

    new_h = generate_password_hash(password, method='pbkdf2:sha256:200000', salt_length=8)
    us = User(username=username, password=str(new_h), email = email)
            
    db.session.add(us)
    db.session.commit()
    return render_template("index.html")


@app.route('/raise_change_form', methods=['POST', 'GET'])
def raise_change_form():
    return render_template("email_form.html")


@app.route('/pass_change', methods=['POST', 'GET'])
def pass_change():
    email = request.form.get("active_email")
    "".join(email.split())
    us = User.query.filter_by(email = email).first()
    if us == None:
        return render_template("email_form.html", content = f"No user with such e-mail adress is registered.")
    psw_record = PswReset.query.filter_by(id_user = us.id_user).first()
    if psw_record != None:
        if psw_record.activated == False:
            key = psw_record.reset_key
        else:
            psw_record.reset_key = str(make_key())
            key = psw_record.reset_key
            psw_record.activated = False
    else:
        key = str(make_key())
        reset = PswReset(reset_key = key, id_user = us.id_user, activated = False)
        db.session.add(reset)
    db.session.commit()
    session['my_key'] = key
    print("Originally, I would send a message to adres " + email + " with content:", file=sys.stderr)
    print("In order to change your password, follow the 'https://localhost:443/show_changepass_form' link", file=sys.stderr)
    return render_template("email_form.html")


@app.route('/show_changepass_form', methods=['POST', 'GET'])
def show_changepass_form():
    return render_template("change_password_form.html")


@app.route('/update_password', methods=['POST', 'GET'])
def update_password():
    key = session.get('my_key', None)
    reset = PswReset.query.filter_by(reset_key = str(key)).first()
    if reset.activated == True:
        return render_template("email_form.html", content = f"Apparently, you've already used that reset URL. Please, make a new request here.")
    reset.activated = True
    pass1 = request.form.get("newpass")
    pass2 = request.form.get("newpass_conf")
    "".join(pass1.split())
    "".join(pass2.split())
    if pass1 != pass2:
        return render_template("change_password_form.html", content=f"Your passwords are different. Try again.")
    if verify_strong_password(pass1) == False:
        return render_template("change_password_form.html", content=f"Your password is not strong enough. Make sure it contains 8 symbols, letters both in upper case and lower case, as well as at least one digit. ")
    new_h = generate_password_hash(pass1.encode('utf-8'), method='pbkdf2:sha256:200000', salt_length=8)
    us = User.query.filter_by(id_user = reset.id_user).first()
    us.password = str(new_h)
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
    "".join(servicename.split())
    "".join(password.split())
    "".join(masterp.split())

    if verify_strong_password(password) == False:
        return "Your password is not secure enough.. I'm just worried"
    
    pk = hashlib.sha256(masterp.encode('utf-8'), salt).digest()
     
    new_en = aes_encrypt(str(password), pk)
    ac = Account(id_user=current_user.id_user, service = servicename, password=new_en)
            
    db.session.add(ac)
    db.session.commit()
    services_l = Account.query.filter_by(id_user = current_user.id_user).all()
    return render_template("services.html", services_l = services_l)


@app.route('/form_get_service', methods=['POST', 'GET'])
def form_get_service():
    return render_template("service_get_form.html")

@app.route('/get_service_password', methods=['POST', 'GET'])
def get_service_password():
    service = request.form.get("service")
    masterp = request.form.get("master_get")
    "".join(service.split())
    "".join(masterp.split())
    try:
        ac = Account.query.filter_by(id_user = current_user.id_user, service = service).first()
        pk = hashlib.sha256(masterp.encode('utf-8')).digest()

        passw = aes_decrypt(ac.password, pk)
        return "Your password: " + passw.decode('utf-8')
    except:
        return "There is a high probability that this service is not stored"


def verify_strong_password(password):
    rules = [lambda password: any(x.isupper() for x in password),
            lambda password: any(x.islower() for x in password),
            lambda password: any(x.isdigit() for x in password),
            lambda password: len(password) >= 8]
    if all(rule(password) for rule in rules):
        return True
    else:
        return False

def check_on_honey(name):
    if name == "admin00":
        us = User.query.filter_by(username = name).first()
        message = "Originally, I would send e-mail to adress " + str(us.email) + " with warning about an attemp to log in into the administrator account"
        return message
    else:
        return None


def aes_encrypt(password, pk):
    raw_pass = pad(password.encode('utf-8'), 16)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(pk, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw_pass))


def aes_decrypt(new_en, pk):
    encrypted = base64.b64decode(new_en)
    iv = encrypted[:16]
    cipher = AES.new(pk, AES.MODE_CBC, iv)
    message = encrypted[16:]
    return unpad(cipher.decrypt(message), 16)


def get_password(user):
    obj = User.query.filter_by(username = user).first()
    if isinstance(obj, User):
        return obj.password
    else:
        return render_template("temp.html", content=f"Cant return password for some reason."), 403
    
    
def get_current_id(user):
    obj = User.query.filter_by(username = user).first()
    if isinstance(obj, User):
        return obj.id_user
    else:
        return render_template("temp.html", content=f"Can't return user's ID."), 403


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('temp.html', reason=e.description), 400

def make_key():
    return uuid.uuid4()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')