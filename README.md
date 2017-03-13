JSONLD-Java Tools
-----------------

Tools for using JSONLD-Java

[![Build Status](https://travis-ci.org/jsonld-java/jsonld-java-tools.svg?branch=master)](https://travis-ci.org/jsonld-java/jsonld-java-tools) 
[![Coverage Status](https://coveralls.io/repos/jsonld-java/jsonld-java-tools/badge.svg?branch=master)](https://coveralls.io/r/jsonld-java/jsonld-java-tools?branch=master)

### Dependencies

* Java-1.8+
* Maven-3

Playground
----------

The JSONLD-Java Playground is a simple application which provides command line access to JSON-LD functions.

### Initial clone and setup

    git clone git@github.com:jsonld-java/jsonld-java-tools.git
    chmod +x ./jsonldplayground

### Usage

run the following to get usage details:

    ./jsonldplayground --help

### Support for basic authentication

Authentication involves 5 options:

| Option                | Description                       |
|-----------------------|-----------------------------------|
| `--username <user>`   | username for basic authentication |
| `[--password <pass>]` | password for basic authentication, defaults to the value of the `PASSWORD` environment variable, if any, or the empty string. |
| `[--authHost <host>]` | host scope of the authentication, defaults to 'localhost'  |
| `[--authPort <port>]` | port scope of the authentication, defaults to '443'  |
| `[--isecure]`         | Similar to `curl -k` or `curl --insecure`: if unspecified, all SSL connections are secure by default; if specified, trust everything (do not use for production!) |


