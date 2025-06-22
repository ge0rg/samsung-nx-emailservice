#!/bin/bash

WEBDIR=$(dirname $0)/data/

while FN=$(inotifywait -q -e close_write -r --format %w%f $WEBDIR) ; do
	FOLDER=$(basename $(dirname "$FN"))
	echo "New upload in $FOLDER - $FN"
	# WARNING: do not run ImageMagick on attacker-supplied content!
	convert "$FN" -quality 90 "$FN.jpg" && mv "$FN.jpg" "$FN"
	python3 upload_xmpp.py -t image/jpeg "$FN"
done
