```
               _      _
   _______  __(_)____(_)___  ___
  / ___/ / / / / ___/ / __ \/ _ \
 / /__/ /_/ / (__  ) / / / /  __/
 \___/\__,_/_/____/_/_/ /_/\___/

```

Cuisine is a task automation tool written in Python that provides a platform
neutral abstraction over your operating system. It is designed as a simple
flat API to interact with one or more servers, making it easy to do remote
scripting piloted by Python.


# FAQ

## Why should I use Cuisine?

Here are a few reasons why you would use Cuisine:

- You prefer to use Python rather than shell scripts for automation
- You prefer a simple solution to a complex framework
- You want to have full control over your automation process

## How does Cuisine compare to others?

Overall, Cuisine offers a simple abstraction layer over fundamental OS operations that make it easier to automate
administration, building, provisioning, deployments and other devops-related tasks.

- [Fabric](https://www.fabfile.org/): Fabric provides a way to run arbitrary
  commands across hosts, and sits at a lower level than Cuisine. In fact, the
  previous version of Cuisine was built on top of Fabric.
- [Salt](https://docs.saltproject.io/en/latest/): Salt provides a high-level
  declarative interface to systems, while Cuisine offers a lower level API that
  you can use to write your own scripts or logic.

## Which systems are supported by Cuisine?

Currently, Cuisine is only intended to work on UNIX systems, and has specialised functions
for the following systems:

- Packages: apt (Debian,Ubuntu), yum (Redhat, Fedora), pkg (FreeBSD)


# References

- [Mitogen](https://mitogen.networkgenomics.com/)
