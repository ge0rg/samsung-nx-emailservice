#!/usr/bin/env python3

import os
import toml
from flask import Flask, request, redirect, url_for, make_response
from xml.etree import ElementTree
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.from_file("config.toml", load=toml.load)

@app.route('/')
def home():
    return "Samsung NX will never die!"

@app.route('/social/columbus/email',methods = ['POST', 'GET'])
def sendmail():
    if request.method == 'POST':
        print('files', request.files)
        print('form', request.form)
        if 'message' in request.files:
            xml = ElementTree.parse(request.files['message'])
            sender = xml.find('sender').text
            if not sender in app.config['SENDERS']:
                print("Sender %s not in whitelist %s" % (sender, app.config['SENDERS']))
                return make_response("You are not whitelisted", 401)
            recipients = [e.text for e in xml.find('receiverList').findall('receiver')]
            title = xml.find('title').text
            body = xml.find('body').text.replace("\nlanguage_sh100_utf8", "")
            print("From:", sender)
            print("To:", ", ".join(recipients))
            print("Subject:", title)
            print(body)
            store = os.path.join(app.config['UPLOAD_FOLDER'], sender)
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

