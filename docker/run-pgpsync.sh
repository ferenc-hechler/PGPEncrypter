#!/bin/sh
BASEDIR=$(dirname "$0")
cd "$BASEDIR"
BASEDIR=$(pwd)

docker run -d --name pgpsync -v "$BASEDIR/input:/INPUT" -v "$BASEDIR/output:/OUTPUT" -v "$BASEDIR/appdata:/APPDATA" pgpenc
