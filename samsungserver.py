#!/usr/bin/env python3

import os
import toml
import base64
import hmac
import email.utils
import time

from mysession import MySession
import samsungxml

from flask import Flask, abort, jsonify, request, redirect, render_template, url_for, make_response
from xml.etree import ElementTree as ET
from werkzeug.utils import secure_filename

from flask_autoindex import AutoIndex
from flask_mail import Mail, Message

from mastodon import Mastodon

app = Flask(__name__)
app.config.from_file("config.toml", load=toml.load)

mysession = MySession(app)

mail = Mail(app)

mastodon = Mastodon(access_token=app.config['MASTODON_TOKEN'], api_base_url=app.config['MASTODON_BASE_URL'])

# auto-index (for "secret" directories)
idx = None
if app.config['INSECURE_DOWNLOAD']:
    idx = AutoIndex(app, browse_root=app.config['UPLOAD_FOLDER'], add_url_rules=False)

def mangle_addr(email, secret=app.config['SECRET']):
    key = bytes(secret, 'utf-8')
    sig = hmac.new(key, bytes(email, 'utf-8'), digestmod='sha256')
    return base64.urlsafe_b64encode(sig.digest()[:15]).decode('ascii')

def email_store_files(addr, recipient, files):
    dirname = mangle_addr(addr)
    store = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
    os.makedirs(store, exist_ok = True)
    for f in files.getlist('binary'):
        fn = os.path.join(store, secure_filename(f.filename))
        app.logger.info("Saving %s", fn)
        f.save(fn)

def email_mastodon_post(body, files):
    media_ids = []
    body_alt = body.split('~')
    images = files.getlist('binary')
    if len(body_alt) != 1 + len(images):
        app.logger.warning('Body does not have enough alt text for %d images: %s', len(images), body)
        abort(400, 'No alt-text')
    body = body_alt.pop(0) + '\n\n' + app.config['MASTODON_POSTSCRIPT']
    for f in images:
        f_meta = mastodon.media_post(f.read(), f.mimetype, description=body_alt.pop(0))
        media_ids.append(f_meta['id'])
        app.logger.debug("Posted image: %s", f_meta)
    app.logger.debug("Image IDs: %s", ', '.join([str(i) for i in media_ids]))
    meta = mastodon.status_post(body, media_ids=media_ids, visibility=app.config['MASTODON_VISIBILITY'])
    app.logger.debug("Posted status: %s", meta)

def social_store_file(session, data, filename):
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(session.dir))
    if not os.path.isdir(store):
        abort(401, "No upload folder")
    fn = os.path.join(store, secure_filename(filename))
    app.logger.info("Saving %s" % fn)
    with open(fn, "wb") as f:
        f.write(data)

def social_mastodon_post(session, data, content_type):
    if not 'media' in session:
        session.media = []
    body = session.content
    body_alt = body.split('~')
    body = body_alt.pop(0) + '\n\n📷️ ' + session.album + '\n\n' + app.config['MASTODON_POSTSCRIPT']

    # get N'th alt-text for N'th image upload
    f_meta = mastodon.media_post(data, content_type, description=body_alt[len(session.media)])
    app.logger.debug("Posted image: %s", f_meta)
    session.media.append(f_meta['id'])

    app.logger.debug("Image IDs: %s", ', '.join([str(i) for i in session.media]))
    app.logger.debug(body_alt)
    if len(body_alt) == len(session.media):
        # all alt-text elements have been consumed, this was the last photo
        meta = mastodon.status_post(body, media_ids=session.media, visibility=app.config['MASTODON_VISIBILITY'])
        app.logger.debug("Posted status: %s", meta)
    mysession.store(session)


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

# NX300 "AllShare" login
@app.route('/security/sso/userprofiles/authentication/emailid', methods=['POST'])
def authentication_emailid():
    d = request.get_data()
    app.logger.debug("POST payload: %s", d)
    xml = ET.fromstring(d)
    creds = samsungxml.extract_userAuthRequest(xml)
    if not creds['user'] in app.config['SENDERS']:
        return "Login failed", 401
    app.logger.warn("Not yet reverse-engineered API endpoint")
    abort(500, 'Unknown API')


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
    if not d:
        abort(400, 'Empty POST payload') # sometimes sent by NX300?!
    xml = ET.fromstring(d)
    method = xml.attrib["Method"]
    app.logger.debug("auth %s for site %s", method, site)
    if method == 'logout':
        return "Logged out for real!"
    if site in OAUTH_SITES:
        return "OAuth not supported", 401
    creds = samsungxml.extract_credentials(xml)
    app.logger.debug("site %s auth request: %s", site, creds)
    if not creds['user'] in app.config['SENDERS']:
        return "Login failed", 401
    # HACK: create mangled folder name as pseudo-session
    dirname = mangle_addr(creds['user'])
    session = mysession.load(None)
    session.user = creds['user']
    session.dir = dirname
    mysession.store(session)
    app.logger.info(f"User {creds['user']} logged in, creating {dirname}, session {session.sid}...")
    store = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
    os.makedirs(store, exist_ok = True)
    t= render_template('response-login.xml',
            sessionkey=session['sid'],
            csk=session['sid'],
            screenname="Samsung NX Lover"
        )
    app.logger.debug(t)
    return t

@app.route('/<string:site>/photo',methods = ['POST'])
def photo(site):
    if not site in SITES:
        abort(404)
    d = request.get_data()
    xml = ET.fromstring(d)
    photo = samsungxml.extract_photo(xml)
    sid = photo['sessionkey']
    session = mysession.load(sid)
    session.site = site
    app.logger.debug("Session: %s", session)
    if not 'user' in session:
        app.logger.warning("Unknown session key %s: %s", photo['sessionkey'], session['sid'])
        abort(401, "Session expired")
    session.update(photo)
    mysession.store(session)
    app.logger.debug("site %s photo request: %s from user: %s", site, photo, session['user'])
    dirname = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(session['dir']))
    app.logger.info(f"Upload {photo['filename']} into {dirname}...")
    if not os.path.isdir(dirname):
        app.logger.warning(f"Upload directory for {session['user']} does not exist: {dirname}")
        abort(401)
    return render_template('response-upload.xml', **photo)

@app.route('/<string:site>/video',methods = ['POST'])
def video(site):
    if not site in VIDEO_SITES:
        abort(404)
    d = request.get_data()
    xml = ET.fromstring(d)
    photo = samsungxml.extract_video(xml)
    app.logger.debug("site %s video request: %s", site, photo)
    sid = photo['sessionkey']
    session = mysession.load(sid)
    session.site = site
    if not 'user' in session:
        app.logger.warning("Unknown session key %s: %s", photo['sessionkey'], session['sid'])
        abort(401, "Session expired")
    session.update(photo)
    mysession.store(session)
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(photo['sessionkey']))
    if not os.path.isdir(store):
        abort(401)
    return render_template('response-upload.xml', **photo)

@app.route('/upload/<string:sessionkey>/<string:filename>', methods = ['PUT'])
def upload(sessionkey, filename):
    d = request.get_data()
    app.logger.debug('request from %s, %s length: %d', sessionkey, filename, len(d))
    session = mysession.load(sessionkey)
    if not 'user' in session:
        abort(401, "Session expired")
    policy = app.config['ACTIONS'].get(session.site, 'store')
    if policy == 'store':
        social_store_file(session, d, filename)
    elif policy == 'mastodon':
        social_mastodon_post(session, d, request.content_type)
    return render_template('response-status.xml', status='succ')

@app.route('/social/columbus/email',methods = ['POST', 'GET'])
def sendmail():
    if request.method == 'POST':
        app.logger.debug('files: %s', request.files)
        app.logger.debug('form: %s', request.form)
        if 'message' in request.files:
            xml = ET.parse(request.files['message'])
            sender = xml.find('sender').text
            name, addr = email.utils.parseaddr(sender)
            if not addr in app.config['SENDERS']:
                app.logger.warning("Sender %s not in whitelist %s" % (addr, app.config['SENDERS']))
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
                    email_store_files(addr, r, request.files)
                    recipients.remove(r)
                elif policy == 'mastodon':
                    email_mastodon_post(body, request.files)
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
        else:
            app.logger.warning("No 'message' in POST or unpatched Flask")
            abort(400, "No 'message' in POST or unpatched Flask")
        return make_response("Yay", 200)
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port=8080)

