# Variants

Cuisine supports **variants**, which are typically common functionality, such
as installing packages or managing users, which might have different
implementations based on the context.

Variant functions are all suffixed by their variants and have a corresponding
dispatcher function. For instance, the `package_install` dispatches its
arguments to `package_install_apt` (*apt variant*) or `package_install_yum`
(*yum variant*).

Selecting the current default variant is done using detection functions
such as `detect_package`, or can be manually set using `select_package`

In general, here are how variant work:

- `select_<GROUP>` (eg. `select_package("yum")`), selects the default
  variant for the given group of API functions.
- `detect_<GROUP>` (eg. `detect_package()`), detects the recommended/preferred
  variant for the given group of API. The behaviour will change based
  on the host and system.
- `<GROUP>_<FUNCTION>_<VARIANT>` (eg. `package_install_yum`) is the variant-specific
   implementation of the functionality.
- `<GROUP>_<FUNCTION>` (eg. `package_install`) dispatches to  the variant-specific
    based on the currently selected default.

In short, unless you explicitly want to use a specific variant implementation,
you can use the generic dispatching functions.
