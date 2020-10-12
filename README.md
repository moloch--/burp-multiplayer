# Burp Multiplayer

A Multiplayer Plugin for Burp


## Setup

Install extension, connect multiple instances to the same [RethinkDB](https://rethinkdb.com/) instance. Only in-scope items will be sync'd. You can use `rethinkdb.sh` to start a locally running instance in a Docker container. You can use `ssh -L <local_port>:localhost:<driver_port> <ip_of_rethinkdb_server>` to access a remote RethinkDB instance using an SSH tunnel. 

#### RethinkDB Security
 
 * https://rethinkdb.com/docs/security/
 
