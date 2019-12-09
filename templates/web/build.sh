#!/bin/sh

npm run build:prod
cd dist
zip -r moka-admin.zip ./*

scp moka-admin.zip root@47.98.199.111:/usr/share/nginx/html
rm -rf ./moka-admin.zip
