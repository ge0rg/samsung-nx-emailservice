#!/usr/bin/env python3

import os
import toml
import base64
import hmac
import email.utils
import logging
import json
import time

import samsungxml

from flask import Flask, abort, jsonify, request, redirect, render_template, url_for, make_response
from xml.etree import ElementTree as ET
from werkzeug.utils import secure_filename

from flask_autoindex import AutoIndex

from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_file("config.toml", load=toml.load)

mail = Mail(app)

# auto-index (for "secret" directories)
idx = None
if app.config['INSECURE_DOWNLOAD']:
    idx = AutoIndex(app, browse_root=app.config['UPLOAD_FOLDER'], add_url_rules=False)

def mangle_addr(email, secret=app.config['SECRET']):
    key = bytes(secret, 'utf-8')
    sig = hmac.new(key, bytes(email, 'utf-8'), digestmod='sha256')
    return base64.urlsafe_b64encode(sig.digest()[:15]).decode('ascii')

def store_email_files(addr, recipient, files):
    dirname = mangle_addr(addr)
    store = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
    os.makedirs(store, exist_ok = True)
    for f in files.getlist('binary'):
        fn = os.path.join(store, secure_filename(f.filename))
        app.logger.info("Saving %s", fn)
        f.save(fn)


@app.route('/<path:path>')
def autoindex(path='.'):
    if idx:
        return idx.render_autoindex(path, sort_by='name', order=1)
    abort(404)


@app.route('/')
def home():
    host = (request.headers.get('Host') or "")
    if host == "www.yahoo.co.kr":
        resp = make_response("YAHOO!", 200)
        resp.set_cookie('samsung', 'hotspot', domain='.yahoo.co.kr')
        return resp
    if host == "www.msn.com":
        resp = make_response("MSN", 200)
        resp.set_cookie('samsung', 'hotspot', domain='.msn.com')
        return resp
    return render_template('index.html', useragent=request.user_agent)

# queried by ST1000
@app.route('/security/sso/initialize/time')
def init_time():
    return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><initializeResult><currentServerTime>{int(time.time()*1000)}</currentServerTime></initializeResult>'

# queried by ST1000, response syntax unknown
@app.route('/social/columbus/serviceproviders/list')
def serviceproviders_list():
    return "TODO"

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

@app.route('/<string:site>/photo',methods = ['POST'])
def photo(site):
    if not site in SITES:
        abort(404)
    d = request.get_data()
    xml = ET.fromstring(d)
    photo = samsungxml.extract_photo(xml)
    logging.warning("site %s photo request: %s", site, photo)
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(photo['sessionkey']))
    if len(photo['sessionkey']) != 20 or not os.path.isdir(store):
        abort(401)
    return render_template('response-upload.xml', **photo)

@app.route('/<string:site>/video',methods = ['POST'])
def video(site):
    if not site in VIDEO_SITES:
        abort(404)
    d = request.get_data()
    xml = ET.fromstring(d)
    photo = samsungxml.extract_video(xml)
    logging.warning("site %s video request: %s", site, photo)
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(photo['sessionkey']))
    if len(photo['sessionkey']) != 20 or not os.path.isdir(store):
        abort(401)
    return render_template('response-upload.xml', **photo)

@app.route('/upload/<string:sessionkey>/<string:filename>', methods = ['PUT'])
def upload(sessionkey, filename):
    d = request.get_data()
    logging.warning('request from %s, %s length: %d', sessionkey, filename, len(d))
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(sessionkey))
    if len(sessionkey) != 20 or not os.path.isdir(store):
        abort(401)
    fn = os.path.join(store, secure_filename(filename))
    logger.warning("Saving %s" % fn)
    with open(fn, "wb") as f:
        f.write(d)
    return "Success!"

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
            app.logger.debug("From: %s", sender)
            app.logger.debug("To: %s", ", ".join(recipients))
            app.logger.debug("Subject: %s", title)
            app.logger.debug("| %s", body)
            for r in sorted(recipients):
                policy = app.config['ACTIONS'].get(r, 'mail')
                app.logger.info("Recipient %s policy is %s!", r, policy)
                if policy == 'store':
                    store_email_files(addr, r, request.files)
                    recipients.remove(r)
            if not recipients:
                app.logger.info("No email recipients left!")
                return make_response("Yay", 200)
            
            app.logger.debug("Sending email to %s", ",".join(recipients))
            msg = Message(subject=title, sender=sender, recipients=recipients)
            msg.body = body
            for f in request.files.getlist('binary'):
                msg.attach(f.filename, f.mimetype, f.read())
            # TODO: exception handling
            mail.send(msg)
        return make_response("Yay", 200)
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port=8080)

