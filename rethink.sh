#!/bin/bash

docker run -p 127.0.0.1:8081:8080 -p 127.0.0.1:28015:28015 -p 127.0.0.1:29015:29015 --name rethinkdb -v "$PWD:/data" -d rethinkdb
