#!/usr/bin/env python3

import json
import os
import uuid

from werkzeug.utils import secure_filename

class Session(dict):
    # dot.notation access to dictionary attributes
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


# Flask sessions store everything in secure cookies. We don't want cookies
# and we can't store any data on the client anyway
class MySession:

    def __init__(self, app):
        self.app = app
        self.SESSION_FOLDER = app.config['SESSION_FOLDER']

    def gen_fn(self, sid = None):
        if not sid:
            sid = uuid.uuid4().hex
        fn = secure_filename(sid + ".json")
        return sid, os.path.join(self.SESSION_FOLDER, fn)

    def clear(self, session):
        if 'sid' in session:
            sid, fn = self.gen_fn(session.sid)
            os.remove(fn)
        session.clear()

    def load(self, sid):
        try:
            sid, fn = self.gen_fn(sid)
            session = Session(json.load(open(fn, "r")))
            session.sid = sid
        except Exception as e:
            self.app.logger.warn("Invalid session %s: %s", sid, e)
            session = Session(sid=sid)
        return session

    def store(self, session):
        sid, fn = self.gen_fn(session.pop('sid', None))
        with open(fn, "w") as f:
            json.dump(session, f)
        session.sid = sid
        return sid

