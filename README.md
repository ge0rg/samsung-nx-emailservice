# Flask-based Samsung NX Camera Upload Server

This code emulates Samsung's NX email and social media upload service. It will
not send an email but merely store the uploaded files in a local folder and
print the email details.

This can be used to forward the "sent" images to a photo gallery, actually send
emails or whatever.

This code is using Flask, but as the Samsung cameras are not fully compliant
with the HTTP standard, we need to apply a minor fix (`flask.diff` for Python
3.9, flask 2.1.2).

## Supported models

The following camera models (generations) support sending e-mails:

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

## Deployment

1. Change the path, secret and white-listed sender emails in `config.toml`

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
