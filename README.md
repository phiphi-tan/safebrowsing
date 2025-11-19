[![Build Status](https://travis-ci.org/google/safebrowsing.svg?branch=master)](https://travis-ci.org/google/safebrowsing)

# Reference Implementation for the Usage of Google Safe Browsing APIs (v4)

The `safebrowsing` Go package can be used with the
[Google Safe Browsing APIs (v4)](https://developers.google.com/safe-browsing/v4/)
to access the Google Safe Browsing lists of unsafe web resources. Inside the
`cmd` sub-directory, you can find two programs: `sblookup` and `sbserver`. The
`sbserver` program creates a proxy local server to check URLs and a URL
redirector to redirect users to a warning page for unsafe URLs. The `sblookup`
program is a command line service that can also be used to check URLs.

This **README.md** is a quickstart guide on how to build, deploy, and use the
`safebrowsing` Go package. It can be used out-of-the-box. The GoDoc and API
documentation provide more details on fine tuning the parameters if desired.

# Setup

To use the `safebrowsing` Go package you must obtain an _API key_ from the
[Google Developer Console](https://console.developers.google.com/). For more
information, see the _Get Started_ section of the Google Safe Browsing APIs (v4)
documentation.

# How to Build

To download and install from the source, run the following command:

```bash
go install
go get github.com/google/safebrowsing
```

The programs below execute from your `$GOPATH/bin` folder.
Add that to your `$PATH` for convenience:

```
export PATH=$PATH:$GOPATH/bin
```

# Proxy Server

The `sbserver` server binary runs a Safe Browsing API lookup proxy that allows
users to check URLs via a simple JSON API.

1.  Once the Go environment is setup, run the following command with your API key:

    ```bash
    go install github.com/google/safebrowsing/cmd/sbserver@latest
    # go get github.com/google/safebrowsing/cmd/sbserver / # OLD COMMAND, DEPRECATED
    sbserver -apikey $APIKEY
    ```

    With the default settings this will start a local server at **127.0.0.1:8080**.
    You can also change the address via the `-srvaddr` flag

2.  Automated URL Blacklist Submission

    This script asynchronously looks up URLs against the online GoogleSafeBrowsing database, submits missing URLs, and polls a local server for updates.

    > Active threat categories: SOCIAL_ENGINEERING (phishing)  
    > Inactive threat categories: MALWARE, UNWANTED_SOFTWARE

    Logs: Automatically saved in `./logs` directory

    Usage:

    ```bash
    python script.py --url <single_url>  # Look up a single URL
    python script.py --file <file_path>  # Look up URLs from a file (one per line)

    python script.py --url http://example.com \
                 --poll_interval 60 # optional: polling interval (in minutes), default = 1hr
                 --poll_timeout 100 # optional: polling timeout (in minutes), default = 14 days
    ```

# Command-Line Lookup

The `sblookup` command-line binary is another example of how the Go Safe
Browsing library can be used to protect users from unsafe URLs. This
command-line tool filters unsafe URLs piped via STDIN. Example usage:

```
$ go get github.com/google/safebrowsing/cmd/sblookup
$ echo "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/" | sblookup -apikey=$APIKEY
  Unsafe URL found:  http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/ [{testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/ {MALWARE ANY_PLATFORM URL}}]
```

# Safe Browsing System Test

To perform an end-to-end test on the package with the Safe Browsing backend,
run the following command:

```
go test github.com/google/safebrowsing -v -run TestSafeBrowser -apikey $APIKEY
```
