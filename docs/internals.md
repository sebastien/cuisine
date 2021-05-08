# Internals


## API

The `cuisine.api` is implemented in a modular way, where specific groups
of functions (eg. *file*, *dir*, *user*, etc) are implemented as separate modules.

The first version of Cuisine had a single-file flat-namespace designed
specifically for being compact and easily discoverable from the REPL using
tab completion. We wanted to keep this discoverability with Cuisine 2, but as the number
of functions grew,  we decided to wrap functions in API subclassess. This makes
the code more modular, while also making it possible to manage concurrent sessions
with different configurations and variants.

The `cuisine.api` module is able to introspect its submodules and to
generate a *stub* that contains a flat-namespace version that is able
to dispatch the method calls to the proper subclasses, supporting variants
and options transparently.

The actual cuisine API interface is defined as `cuisine.api._stub.API` class,
and the implementation in `cuisine.api._impl.API` class. Both of these
 files can be generated using the `cuisine.api.toSource()` function, or running
 directly the `cuisine.api` module:

 ```shell
 # Outputs the Python source code for the API stub.
 python3 -m cuisine.api
 ```

## API Modules

As a result of this slightly unusual approach, any `cuisine.api` submodule
needs to subclass `cuisine.api.APIModule` and invoke Cuisine API functions
using `self.api`.

Each Cuisine API module needs also to decorate its exported API methods
using the `@expose` decorator:

```python
class Date(APIModule):
	@expose
	@requires("date")
	def date_now( self ) -> str:
		self.api.run("data +'%Y-%M-%d'").value
```

The `@requires` decorator makes it clear that this function requires the `date`
command.
