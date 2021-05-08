# API

Cuisine's API is designed to be used both interactively and non-interactively
using an editor that support type annotations, which translates into the API
being flat-namespaced and fully discoverable from the cuisine top-level module,
and which also comes with full type annotations.

For instance, typing `cuisine.file_`  folowed by a *TAB* from the Python
interactive prompt should show you *all the functions* you can do for files.


## Groups

The API is decomposed in functional groups that make it easy to see what
can be done:

- `file`
- `dir`
- `user`
- `group`
- `package`
- `command`
- `text`

with additional API to manage the configuration and the environments:

- `connect_`
- `enable_`

## Variants

- `select_`

## Internals

Under the hood, the API is implemented as classes that implement a common contract.
For instance, users and groups can be added, removed. Files can be read and written,
packages can be installed and uninstalled.

```
User.add → user_add
User.remove → user_remove
```

Variants are supported in the same way. For instance, RPM and DEB packages
are each implemented in their separated modules and mapped to specific
flat names:

'RPM.add → packages_add_rpm'
'DEV.add → packages_add_deb'

in parallel, the `Packages.add` API, mapped to ` packages_add` will dispatch
to the corresponding package type.
