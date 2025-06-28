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
app.config.from_file(os.getenv("CONFIG", "config.toml"), load=toml.load)

mysession = MySession(app)

mail = Mail(app)

def get_config(action, instance):
    """get the config dict for a given action ('SHELL', 'MASTODON') and its respective instance, if given. Instances inherit the default action config!"""
    if instance: # and app.config[module].get(instance):
        # get defaults and override with specific config
        conf = app.config[action]
        conf.update(app.config[action][instance])
        return conf
    else:
        return app.config[action]

MASTODON_INSTANCES = {}

def get_mastodon_instance(instance):
    app.logger.debug("Requested mastodon instance for %s", instance)
    if instance in MASTODON_INSTANCES:
        app.logger.debug("Found %s", MASTODON_INSTANCES[instance].api_base_url)
        return MASTODON_INSTANCES[instance]
    conf = get_config('MASTODON', instance)
    masto = Mastodon(
        access_token=conf['TOKEN'],
        api_base_url=conf.get('BASE_URL'),
        user_agent='samsung-nx-emailservice')
    masto._appconfig = conf
    MASTODON_INSTANCES[instance] = masto
    app.logger.debug("Initialized %s", MASTODON_INSTANCES[instance].api_base_url)
    return masto


# auto-index (for "secret" directories)
idx = None
if app.config['INSECURE_DOWNLOAD']:
    idx = AutoIndex(app, browse_root=app.config['UPLOAD_FOLDER'], add_url_rules=False)

def mangle_addr(email, secret=app.config['SECRET']):
    key = bytes(secret, 'utf-8')
    sig = hmac.new(key, bytes(email, 'utf-8'), digestmod='sha256')
    return base64.urlsafe_b64encode(sig.digest()[:15]).decode('ascii')

def get_action(target, default_action):
    """return the override action from the config or the default action if no override is set"""
    mapping = app.config['ACTIONS'].get(target, default_action)
    if '.' in mapping:
        return mapping.split('.')
    else:
        return (mapping, None)

def update_session_action(session, target=None):
    if target:
        session.site = target
    action, instance = get_action(session.site, 'store')
    session.instance = instance
    if instance:
        session.dir = instance
    return action, instance



def mastodon_post_image(instance, content, content_type, description):
    if content_type == "image/pjpeg":
        content_type = "image/jpeg"
    mastodon = get_mastodon_instance(instance)
    f_meta = mastodon.media_post(content, content_type, description=description)
    app.logger.debug("Posted image: %s", f_meta)
    return f_meta['id']

def email_store_files(instance, addr, recipient, files):
    dirname = mangle_addr(addr)
    if instance:
        dirname = instance
    store = os.path.join(app.config['UPLOAD_FOLDER'], dirname)
    os.makedirs(store, exist_ok = True)
    filenames = []
    for f in files.getlist('binary'):
        fn = os.path.join(store, secure_filename(f.filename))
        app.logger.info("Saving %s", fn)
        f.save(fn)
        filenames.append(fn)
    return filenames

def email_mastodon_post(instance, body, files):
    media_ids = []
    body_alt = body.split('~')
    images = files.getlist('binary')
    if len(body_alt) != 1 + len(images):
        app.logger.warning('Body does not have enough alt text for %d images: %s', len(images), body)
        abort(400, 'No alt-text')
    mastodon = get_mastodon_instance(instance)
    body = body_alt.pop(0) + '\n\n' + mastodon._appconfig['POSTSCRIPT']
    for f in images:
        image_id = mastodon_post_image(instance, f.read(), f.mimetype, body_alt.pop(0))
        f.seek(0)
        media_ids.append(image_id)
    app.logger.debug("Image IDs: %s", ', '.join([str(i) for i in media_ids]))
    meta = mastodon.status_post(body, media_ids=media_ids, visibility=mastodon._appconfig['VISIBILITY'])
    app.logger.debug("Posted status: %s", meta)

def social_store_file(session, data, filename):
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(session.dir))
    os.makedirs(store, exist_ok = True)
    fn = os.path.join(store, secure_filename(filename))
    app.logger.info("Saving %s" % fn)
    with open(fn, "wb") as f:
        f.write(data)

def social_mastodon_post(session, data, content_type):
    if not 'media' in session:
        session.media = []
    body = session.content
    body_alt = body.split('~')
    mastodon = get_mastodon_instance(session.instance)
    body = body_alt.pop(0) + '\n\n📷️ ' + session.album + '\n\n' + mastodon._appconfig['POSTSCRIPT']

    if len(body_alt) == 0:
        abort(400, 'No alt-text')
    if len(body_alt) <= len(session.media):
        abort(400, 'Not enough alt-text')

    # get N'th alt-text for N'th image upload
    image_id = mastodon_post_image(session.instance, data, content_type, body_alt[len(session.media)])
    session.media.append(image_id)

    app.logger.debug("Image IDs: %s", ', '.join([str(i) for i in session.media]))
    app.logger.debug(body_alt)
    if len(body_alt) == len(session.media):
        # all alt-text elements have been consumed, this was the last photo
        meta = mastodon.status_post(body, media_ids=session.media, visibility=mastodon._appconfig['VISIBILITY'])
        app.logger.debug("Posted status: %s", meta)
    mysession.store(session)


@app.route('/<path:path>')
def autoindex(path='.'):
    if idx:
        return idx.render_autoindex(path, sort_by='name', order=1)
    abort(404)


next_redirect = True

def alternate_response(title, redir_to, cookie_domain):
    global next_redirect
    if next_redirect:
        response = redirect(redir_to, 302)
    else:
        response = make_response(title, 200)
        response.set_cookie('samsung', 'hotspot', domain=cookie_domain)
    next_redirect = not next_redirect
    return response

@app.route('/')
def home():
    host = (request.headers.get('Host') or "")
    if host == "gld.samsungosp.com":
        # old response from 2013
        #return make_response("200 OK\n", 200)
        # response as expected by NX mini fw 1.10
        return make_response("", 200, {'ETag': '"deadbeef"', 'Server': 'nginx/notreally'})
    if host == "www.yahoo.co.kr":
        return alternate_response('YAHOO!', 'http://yahoo.com', '.yahoo.co.kr')
    if host == "www.msn.com":
        # WB37F doesn't accept a redirect, wants a cookie instead
        return alternate_response('MSN', 'http://msn.com', '.msn.com')
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
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="OAuth not supported"), 401
    creds = samsungxml.extract_credentials(xml)
    app.logger.debug("site %s auth request: %s", site, creds)
    if not creds['user'] in app.config['SENDERS']:
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="Login failed"), 401
    # HACK: create mangled folder name as pseudo-session
    dirname = mangle_addr(creds['user'])
    session = mysession.load(None)
    session.dir = dirname
    update_session_action(session, site)
    session.user = creds['user']
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
    update_session_action(session, site)
    app.logger.debug("Session: %s", session)
    if not 'user' in session:
        app.logger.warning("Unknown session key %s: %s", photo['sessionkey'], session['sid'])
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="Session expired"), 401
    if 'content' in session and session['content'] != photo['content']:
        app.logger.warning("Content changed, this is a new upload!")
        session.media = []
        session.conent = ""
    session.update(photo)
    mysession.store(session)
    app.logger.debug("site %s photo request: %s from user: %s", site, photo, session['user'])
    dirname = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(session['dir']))
    app.logger.info(f"Upload {photo['filename']} into {dirname}...")
    if not os.path.isdir(dirname):
        app.logger.warning(f"Upload directory for {session['user']} does not exist: {dirname}")
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="Login failed"), 401
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
    update_session_action(session, site)
    if not 'user' in session:
        app.logger.warning("Unknown session key %s: %s", photo['sessionkey'], session['sid'])
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="Session expired"), 401
    session.update(photo)
    mysession.store(session)
    store = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(photo['sessionkey']))
    if not os.path.isdir(store):
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="Login failed"), 401
    return render_template('response-upload.xml', **photo)

@app.route('/upload/<string:sessionkey>/<string:filename>', methods = ['PUT'])
def upload(sessionkey, filename):
    d = request.get_data()
    app.logger.debug('request from %s, %s length: %d', sessionkey, filename, len(d))
    session = mysession.load(sessionkey)
    if not 'user' in session:
        return render_template('response-error.xml',
                errcode=401, errsubcode=0,
                comment="Session expired"), 401
    action, instance = update_session_action(session)
    app.logger.debug("Upload %s action is %s (instance=%s)!", session.site, action, instance)
    if action == 'store':
        social_store_file(session, d, filename)
    elif action == 'mastodon':
        social_mastodon_post(session, d, request.content_type)
    elif action == 'drop':
        pass
    return render_template('response-status.xml', status='succ')

@app.route('/social/columbus/email',methods = ['POST', 'GET'])
def sendmail():
    if request.method == 'POST':
        app.logger.debug('files: %s', request.files.to_dict())
        app.logger.debug('form: %s', request.form.to_dict())
        if 'message' in request.files:
            for ua in request.headers.get_all('user-agent'):
                app.logger.debug("User-Agent: %s", ua)
            xml = ET.parse(request.files['message'])
            sender = xml.find('sender').text
            name, addr = email.utils.parseaddr(sender)
            if not addr in app.config['SENDERS']:
                app.logger.warning("Sender %s not in whitelist %s" % (addr, app.config['SENDERS']))
                return render_template('response-error.xml',
                        errcode=401, errsubcode=0,
                        comment="Sender not in whitelist"), 401
            recipients = [e.text for e in xml.find('receiverList').findall('receiver')]
            title = xml.find('title').text
            body = xml.find('body').text.replace("\nlanguage_sh100_utf8", "")
            app.logger.debug("From: %s", sender)
            app.logger.debug("To: %s", ", ".join(recipients))
            app.logger.debug("Subject: %s", title)
            app.logger.debug("| %s", body)
            for r in sorted(recipients):
                action, instance = get_action(r, 'mail')
                app.logger.info("Recipient %s action is %s (instance=%s)!", r, action, instance)
                if action == 'store':
                    email_store_files(instance, addr, r, request.files)
                    recipients.remove(r)
                elif action == 'mastodon':
                    email_mastodon_post(instance, body, request.files)
                    recipients.remove(r)
                elif action == 'drop':
                    recipients.remove(r)
            if not recipients:
                app.logger.info("No email recipients left!")
                return render_template('response-status.xml', status='succ')
            
            app.logger.debug("Sending email to %s", ",".join(recipients))
            msg = Message(subject=title, sender=sender, recipients=recipients)
            msg.body = body
            for f in request.files.getlist('binary'):
                msg.attach(f.filename, f.mimetype, f.read())
            # TODO: exception handling
            mail.send(msg)
        else:
            app.logger.warning("No 'message' in POST or unpatched Flask")
            return render_template('response-error.xml',
                    errcode=400, errsubcode=0,
                    comment="No 'message' in POST or unpatched Flask"), 400
        return render_template('response-status.xml', status='succ')
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug = True, host='0.0.0.0', port=8080)

