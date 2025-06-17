#!/usr/bin/env python3

from argparse import ArgumentParser
from mastodon import Mastodon
from os import path

APP = 'samsung-nx-emailservice'
SCOPES = ['write:statuses', 'write:media']

parser = ArgumentParser()
parser.add_argument('url', help='URL of the mastodon server')
parser.add_argument('-c', '--client-secret', dest='client_file', default=None,
                    help='file in which to store the client credentials (debug purposes only)')
parser.add_argument('-u', '--user-secret', dest='user_file', default='mastodon.secret',
                    help='file in which to store the user credentials (mastodon.secret)')

if __name__ == '__main__':
    args = parser.parse_args()
    # perform client registration
    client_id, client_secret = Mastodon.create_app(
        APP,
        user_agent = APP,
        website = 'https://github.com/ge0rg/samsung-nx-emailservice',
        scopes = SCOPES,
        api_base_url = args.url,
        to_file = args.client_file
    )
    # obtain OAuth URL for user
    mastodon = Mastodon(
        api_base_url=args.url,
        client_id=client_id,
        client_secret=client_secret,
        user_agent=APP
    )
    auth_url = mastodon.auth_request_url(scopes=SCOPES)
    print(f"\nPlease open the following in your browser:\n\n{auth_url}\n")
    # finalize user login
    mastodon.log_in(
        code=input("Enter the OAuth authorization code: "),
        scopes = SCOPES,
        to_file=args.user_file,
    )

