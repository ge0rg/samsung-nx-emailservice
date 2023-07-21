# Flask-based Samsung NX Camera Upload Server

This code emulates Samsung's NX email service. It will not send an email but
merely store the uploaded files in a local folder and print the email details.

This can be used to forward the "sent" images to a photo gallery, actually send
emails or whatever.

This code is using Flask, but as the Samsung cameras are not fully compliant
with the HTTP standard, we need to apply a minor fix (`flask.diff` for Python
3.9, flask 2.1.2).

## Deployment

1. Change the path and email in `config.toml`

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
192.168.1.23   gld.samsungosp.com www.samsungimaging.com www.ospserver.net
```

## NX1/NX500

You can directly write to the root filesystem on DRIMeV cameras:

```
mount / -o remount,rw
echo "192.168.0.11 gld.samsungosp.com www.samsungimaging.com www.ospserver.net snsgw.samsungmobile.com" > /etc/hosts
mount / -o remount,ro
```

## NX300/NX30/NX2000

The DRIMeIV cameras have a read-only rootfs, so you need to put the hosts file onto the SD card and add to `autoexec.sh`:

```
mount --bind /mnt/mmc/hosts /etc/hosts
```

## No support for other camera models

The firmware for other models must be patched to replace the hostname. So far,
no reverse engineering efforts have been made to understand the logic and to
be able to change individual parts.
