# Flask-based Samsung NX Camera Upload Server

This code emulates Samsung's NX email and social media upload service.

You can:

 - send emails
 - post to mastodon
 - store to a directory on the server

This code is using Flask, but as the Samsung cameras are not fully compliant
with the HTTP standard, we need to apply a minor fix (`flask.diff` for Python
3.9, flask 2.1.2).

## Supported models

The following camera models (generations) support sending e-mails or uploading
files (see
[Samsung WiFi Cameras](https://op-co.de/blog/posts/samsung_wifi_cameras/) for
details on the compacts):

- ST1000: doesn't work, using unknown API
- EX2F, ST200F, DV300F: **working**
- WBxxxF: see [camera table](https://op-co.de/blog/posts/samsung_wifi_cameras/#index2h2)
- NX mini (M7MU): **working, see below instructions**
- NX1000 (DRIMeIII): **unknown**
- NX30, NX300(M), NX310, NX2000 (DRIMeIV): **working on NX300**, should work on the other models
- NX500, NX1 (DRIMeV): **working on NX500**, should work equally on NX1

**NX mini weirdness**: when you try to send an email _before_ connecting to a
WiFi network, it will fail or hang. Steps to successfully send an email:

1. Share an image with Flickr or another social network
2. Enter (fake) credentials
3. Establish the WiFi connection
4. On the browser tab showing "Samsung NX will never die!", tap the ⮌ back button
5. Now you are connected to WiFi and you can send the email. Easy!

This is probably a bug, but somebody needs to reverse-engineer the NX mini
firmware to see why it fails.

## Supported sharing services

Tested on NX300, NX mini and NX500:
- Email
- Facebook
- Picasa

## Configuration

### Email

To send emails, you need to configure an SMTP (smarthost) account in
`config.toml`. All photos sent from the camera's "Send email" function will be
sent accordingly, unless you define a different _action_ for an address.

The _action_ method is meant for cameras that only support email uploads and
none of the other social networks, like the NX500. For email addresses, the
supported _actions_ are:

- `email` (default)
- `store`
- `mastodon`

See below for the action values.

### Social Media

Photos and videos sent via any of the supported emulated social media services
will be stored under a subdirectory of the `UPLOAD_FOLDER`. A different
_action_ can be defined:

- `store` (default)
- `mastodon`

See below for the action values.

### Mastodon

Go to Settings / Developer on your Mastodon instance, and create a new
application. You only need to allow `write:statuses` and `write:media`.

Please call it "samsung-nx-emailservice" and link to this repositroy.

Once created, you can copy "your access token" into the `MASTODON_TOKEN`
variable.

### `email` Action

An email will be sent via the smarthost, using the camera-supplied From
address, To address, Subject, and message body.

### `store` Action

All uploaded files will be stored under a subdirectory of the `UPLOAD_FOLDER`.
The subdirectory will be the HMAC-SHA256 hash of the username, protected by
`SECRET` to prevent guessing.

The respective directory can be monitored using inotify to implement further
processing (`inotifywait -q -e close_write -r $UPLOAD_FOLDER`).

### `mastodon` Action

Files uploaded using this action will be converted into a Mastodon post.

You **must** define alt-text for **all** images and videos. For social media,
this is technically required because the camera does not tell in advance how
many files are to be expected. For emails, this is used to help visually
impaired people. Alt-text must follow the body, separated using the tilde
character.

For example, the message body "Holiday shot!\~fancy flower bed\~traffic sign"
must be accompanied by two photos, and will be posted as follows:

> Holiday shot!
> 
> 📷️ *\<camera model if supplied by camera>*
>
> *\<content of config variable MASTODON_POSTSCRIPT>*

Image 1: fancy flower bed

Image 2: traffic sign

### Action example

To redirect all photos uploaded to "Facebook" or sent via email to
"example@mastodon.social" to Mastodon, and to only store photos sent to
"store@example.com", you need to define the following three actions:

```toml
[ACTIONS]
facebook = "mastodon"
"example@mastodon.social" = "mastodon"
"store@example.com" = "store"
```

## Installation

1. Change the path, secret and email / mastodon settings in `config.toml`

1. Add your email server credentials to `config.toml`

1. Install the virtual environment, patch flask, and run the (development) server:

```
python3 -m venv venv
source ./venv/bin/activate
pip3 install -r requirements.txt
patch -p1 < flask.diff
sudo python3 samsungserver.py
```

3. Forward incoming traffic on port 80 to the server (running on `*:8080` by
   default)

4. On your camera, add the IP of your server to `/etc/hosts`:

```
192.168.1.23   gld.samsungosp.com www.samsungimaging.com www.ospserver.net snsgw.samsungmobile.com
# For ST200F and WB850F also add this:
192.168.1.23   www.yahoo.co.kr
# For WB35F, WB36F, WB37F, WB1100F also add this:
192.168.1.23   www.msn.com
```

## NX1/NX500

You can directly write to the root filesystem on DRIMeV cameras:

```
mount / -o remount,rw
echo "192.168.0.11 gld.samsungosp.com www.samsungimaging.com www.ospserver.net snsgw.samsungmobile.com" > /etc/hosts
mount / -o remount,ro
```

## NX300/NX30/NX2000

The DRIMeIV cameras have a read-only rootfs that gets reset on restart. You need to put the `hosts` file onto the SD card and copy it to /etc from `autoexec.sh`:

```
mount / -o remount,rw
cp /mnt/mmc/hosts /etc
mount / -o remount,ro
```

## Custom DNS server

You can add the DNS entries to your local / custom DNS server. **It is not
advised to run a public resolver though!**

You can either add the names to the global `/etc/hosts` file or have a custom
file like `/etc/hosts.samsungnx` which you need to inform the DNS server about.

### dnsmasq

Add your custom hosts file to dnsmasq as follows:

`dnsmasq ... -addn-hosts=/etc/hosts.samsungnx`

## No support for other camera models

The firmware for other models must be patched to replace the hostname. So far,
no reverse engineering efforts have been made to understand the logic and to
be able to change individual parts.
