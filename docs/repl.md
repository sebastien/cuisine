# REPL / Interactive Session

Cuisine is designed to be used both as an API and as an interactive session,
similar to what you would do if you were SSH'ing to a server. The key
feature with an interactive session is that Cuisine is able to keep track
of the API calls so that you can capture the history as a script,
replay it and edit if necessary.

```python
from cuisine import *
session = record("myscript.log")
connect("localhost")
user = run("whoami")
session.end()


```
