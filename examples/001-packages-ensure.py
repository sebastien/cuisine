from cuisine import *

# We're going to see if the package TMux is installed
if not package_available("tmux"):
    fail("Package tmux not available in your distribution")

if not package_installed("tmux"):
    package_install("tmux")

require_package("tmux")
