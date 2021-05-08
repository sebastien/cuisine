# Internals


## API

The `cuisine.api` is implemented in a modular way, where specific groups
of functions (eg. *file*, *dir*, *user*, etc) are implemented in separate modules.
The first version of Cuisine had a single-file flat-namespace designed
specifically for being compact and easily discoverable from the REPL using
tab completion.

We wanted to keep this discoverability with Cuisine 2, but as the number
of functions grew, and as we wanted to support more models of execution
(eg. parallel sessions), we decided to wrap functions in API subclassess.

The `cuisine.api` module is able to introspect its submodules and to
generate a *stub* that contains a flat-namespace version that is able
to dispatch the method calls to the proper subclasses, supporting variants
and options transparently.
