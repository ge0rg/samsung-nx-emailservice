#!/usr/bin/env python3

import os
import toml
import base64
import hmac
import email.utils
import logging
import json
import samsungxml
from flask import Flask, abort, jsonify, request, redirect, render_template, url_for, make_response
from xml.etree import ElementTree as ET
from werkzeug.utils import secure_filename

from flask_autoindex import AutoIndex

app = Flask(__name__)
app.config.from_file("config.toml", load=toml.load)
idx = AutoIndex(app, browse_root=app.config['UPLOAD_FOLDER'], add_url_rules=False)

def mangle_addr(email, secret=app.config['SECRET']):
    key = bytes(secret, 'utf-8')
    sig = hmac.new(key, bytes(email, 'utf-8'), digestmod='sha256')
    return base64.urlsafe_b64encode(sig.digest()[:15]).decode('ascii')

# auto-index (for "secret" directories)
idx = AutoIndex(app, browse_root=app.config['UPLOAD_FOLDER'], add_url_rules=False)

def mangle_addr(email, secret=app.config['SECRET']):
    key = bytes(secret, 'utf-8')
    sig = hmac.new(key, bytes(email, 'utf-8'), digestmod='sha256')
    return base64.urlsafe_b64encode(sig.digest()[:15]).decode('ascii')

@app.route('/<path:path>')
def autoindex(path='.'):
    return idx.render_autoindex(path, sort_by='name', order=1)


@app.route('/')
def home():
    return render_template('index.html')

SITES = [
        # from NX300 reverse engineering
        "facebook", "picasa", "youtube", "photobucket",
        "samsungimaging", "cyworld", "me2day", "poco",
        "weibo", "renren", "vkontakte", "odnoklassniki",
        "kakaostory", "evernote", "skydrive",
        # from NX mini
        "flickr", "dropbox",
        ]

OAUTH_SITES = [
        "skydrive", "flickr", "dropbox",
        ]

VIDEO_SITES = [
        "facebook", "youtube",
        ]

@app.route('/<string:site>/auth',methods = ['POST'])
def auth(site):
    if not site in SITES:
        abort(404)
    d = request.get_data()
    xml = ET.fromstring(d)
    method = xml.attrib["Method"]
    logging.warning("auth %s for site %s", method, site)
    if method == 'logout':
        return "Logged out for real!"
    if site in OAUTH_SITES:
        return "OAuth not supported", 401
    creds = samsungxml.extract_credentials(xml)
    logging.warning("site %s auth request: %s", site, creds)
    if not creds['user'] in app.config['SENDERS']:
        return "Login failed", 401
    # HACK: create mangled folder name as pseudo-session
    dirname = mangle_addr(creds['user'])
    store = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
    os.makedirs(store, exist_ok = True)
    return render_template('response-login.xml',
            sessionkey=mangle_addr(dirname),
            screenname="Samsung NX Lover"
        )

@app.route('/social/columbus/email',methods = ['POST', 'GET'])
def sendmail():
    if request.method == 'POST':
        print('files', request.files)
        print('form', request.form)
        if 'message' in request.files:
            xml = ET.parse(request.files['message'])
            sender = xml.find('sender').text
            name, addr = email.utils.parseaddr(sender)
            if not addr in app.config['SENDERS']:
                print("Sender %s not in whitelist %s" % (addr, app.config['SENDERS']))
                return make_response("You are not whitelisted", 401)
            recipients = [e.text for e in xml.find('receiverList').findall('receiver')]
            title = xml.find('title').text
            body = xml.find('body').text.replace("\nlanguage_sh100_utf8", "")
            print("From:", sender)
            print("To:", ", ".join(recipients))
            print("Subject:", title)
            print(body)
            dirname = mangle_addr(addr)
            store = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
            os.makedirs(store, exist_ok = True)
            for f in request.files.getlist('binary'):
                fn = os.path.join(store, secure_filename(f.filename))
                print("Saving %s" % fn)
                f.save(fn)
        return make_response("Yay", 200)
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port=8080)

