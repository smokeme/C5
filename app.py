import flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = flask.Flask(__name__)
auth = HTTPBasicAuth()

## Ignore
iplist = []
good = []
bad = []

# Filename to share
filename = "file"

# Creds for the admin page
user = 'admin'
pw = 'admin'
users = {
    user: generate_password_hash(pw)
}
@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/admin',methods=['GET'])
@auth.login_required
def admin():
    return flask.render_template('admin.html',iplist=iplist,blacklist=bad,allowed=good)
@app.route('/admin',methods=['POST'])
@auth.login_required
def allow():
    print(flask.request.form)
    ip = flask.request.form['ip']
    useragent = flask.request.form['useragent']
    status = flask.request.form['status']
    print(ip)
    print(status)
    if status == "blacklist":
        bad.append({"ip":ip,"useragent":useragent})
        try:
            iplist.remove({"ip":ip,"useragent":useragent})
        except:
            good.remove({"ip":ip,"useragent":useragent})
    elif status == "allow":
        good.append({"ip":ip,"useragent":useragent})
        try:
            iplist.remove({"ip":ip,"useragent":useragent})
        except:
            bad.remove({"ip":ip,"useragent":useragent})
    return flask.render_template('admin.html',iplist=iplist,blacklist=bad,allowed=good)
@app.route('/<path:text>')
def hello(text):
    if text.endswith(".jpg"):
        ip = flask.request.remote_addr
        useragent = flask.request.headers.get('User-Agent')
        for allowed in good:
            if ip == allowed["ip"]:
                return flask.send_file(filename)
        for blacklisted in bad:    
            if ip == blacklisted["ip"]:
                return flask.abort(400)
        for pending in iplist:    
            if ip == pending["ip"]:
                return flask.abort(404)
        iplist.append({"ip":ip,"useragent":useragent})
        return flask.abort(404)
    return flask.abort(404)
app.run(host="0.0.0.0", port=80)
