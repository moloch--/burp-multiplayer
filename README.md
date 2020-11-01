# Burp Multiplayer

A Multiplayer Plugin for Burp. Sync's in-scope requests/responses, comments, highlights, and collaboratively tracks coverage in realtime.


![Java CI with Gradle](https://github.com/moloch--/burp-multiplayer/workflows/Java%20CI%20with%20Gradle/badge.svg)

![Demo](/.github/demo.gif?raw=true "Demo")


## Setup

[Download and install the extension](https://github.com/moloch--/burp-multiplayer/releases), connect multiple instances to the same [RethinkDB](https://rethinkdb.com/) instance.

For details on setting up RethinkDB see the [wiki](https://github.com/moloch--/burp-multiplayer/wiki/RethinkDB-Setup).
 
__Note:__ This extension relies on a lot of interaction with the RethinkDB database, for the best experience ensure you have a fast connection to the database, and that it has sufficient CPU/memory. Large requests/responses may cause the GUI to become sluggish over slow connections (everything is currently loaded eagerly), consider filtering some of these larger requests in the Options panel.

#### Build From Source

From the root of the project just run `gradle all`, which will build a Jar in `build/libs`. The project is partially developed using NetBean's Swing designer, so to edit certain files you'll need it. WARNING: `master` may not be as stable as tagged releases.


#### RethinkDB Security
 
 * https://rethinkdb.com/docs/security/
 
