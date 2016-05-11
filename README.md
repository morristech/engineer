# engineer

Experimental client-side deployment tool for Go on Google Cloud Platform.  Vaguely similar to App Engine/Heroku but lower level and on GCE.

Composed of 3 parts:

0. `engr` command line tool to create instance groups on GCE and deploy new versions of apps.
0. `engineer` library (has a few environment variables defined + some graceful shutdown socket stuff)
0. agent that runs on the GCE instance, handles stdout/stderr logging and restarts the app if it dies

Apps must be Go executables and are run directly on GCE instances.  Each instance group is run behind its own layer 3 load balancer, so you can have websockets.

# PRE-ALPHA
* almost no docs
* probably lots of bugs
* probably will break a bunch
* may delete all your data forever

## Features
* inspired by heroku + http://12factor.net/
* Go only
* depends on GCE and GCS
* deploys, rollbacks, and environment changes are quick (~10s with fast internet connection)
* other operations (such as sync) are slow (~3m)
* with fancy deploys, you can not interrupt existing requests (`engr <app> config graceful_shutdown true`)
* each app gets its own gcs bucket and 1 or more VMs, so each app requires at least an f1-micro instance (but those are pretty cheap)
* supports Google Cloud Debugger
* no build server (uses cross-compilation)
* no central control server (entirely client side)
* no stub services
* no nginx proxy
* no containers

## Limitations
* cgo will not work because of cross-compilation (for fast/serverless deploys)

## Limitations that may be removed later
* Manual scaling only
* An app is only the go executable, no external resources are copied
* `engr` probably only runs on Mac

# Getting Started
## Installation
0. go get github.com/pushbullet/engineer/engr

## Authentication

The `engr` command line tool uses your `gcloud auth` credentials, so make sure you have run `gcloud auth login` https://cloud.google.com/sdk/gcloud/ and that you have the correct account active (`gcloud auth list`).

## Basic Operation
Commands work like this: `engr <app> <command>`, try `engr environ deploy` and `engr environ status`

Run `engr` to get a list of commands.  They will be documented more at a later point.

# Known Issues
* If multiple people try to run deploys at the same time it will totally break because there is no locking.

# Security
Engineer is equivalent to running your own Go programs on GCE, so the same security rules apply.

* App VMs have minimal scopes by default, but require https://www.googleapis.com/auth/devstorage.read_only which allows the VM to read ALL buckets in the current project
  * If you care about this, you should run your app in a different GCP project
* Apps have decent isolation from each other because they run on different VMs
  * GCE has a default-allow-internal rule you can remove if you want
* The base debian-8 image that is used for instances may not have the latest security updates, to get the latest, compile the image builder with `go install github.com/pushbullet/engineer/image-builder` and then build an image wtih  (`image-builder <project>`) to generate a base image, then set it as the default for your app in `engr.json` like `engr <app> config:set image engr-image-20160511t152353`, then run `engr <app> deploy` to update all instances to the newest base image.
  * You can also run custom commands when setting up the image (using the `-script` argument), the default commands are `apt-get update` and `apt-get upgrade`

# Operation
## Deployment
`engr <app> deploy` builds your Go app and uploads it to the GCS bucket for the app under the current version number (stored in `state.json` in the bucket). `engr` then connects over SSH to each machine and runs `agent update` which will download the latest version and switch over to it.

## Sync
`engr <app> sync` lists all GCE resources and compares them to the desired resources, creating or destroying resources as necessary.  If some property of the instance changes (machine type, agent version, etc) N new instances will be created with the new configuration, then the old instances will be destroyed.  Instances that are destroyed should have 60 seconds to finish processing requests/tasks after app receives `SIGTERM`, but this is not guaranteed.

# GracefulShutdown
Each app can have `"GracefulShutdown": true` in its configuration in `engr.json`.  If this is set, the deploy process will attempt to upgrade to the new version with minimal downtime.

## `"GracefulShutdown": false`
0. Old version of app is sent `SIGTERM`, if it doesn't die after 5 seconds, it is sent `SIGKILL`
0. New version of app is started once old one dies

## `"GracefulShutdown": true`
0. New version of app is started
0. After 5 seconds, old version of app will get `SIGTERM`, app is responsible for eventually dying, it is not killed

NOTE: Both versions will receive traffic for some period of time between 5 seconds and when the old version stops accepting new connections

NOTE: For this process to work, the app must bind the socket with the `SO_REUSEPORT` option, which is done in `engineer.ListenAndServe()`, so that two versions of the app can share the same port.

## How to use GracefulShutdown

### Server
0. Catch the `SIGTERM` signal so your app doesn't die
0. Stop listening for traffic
0. Exit when requests are complete (ideally within 60 seconds in case instance is shutting down)

NOTE: `engineer.ListenAndServe()` does steps 1 and 2

### Worker
0. Catch the `SIGTERM` signal so your app doesn't die
0. Stop processing new tasks and exit (ideally within 60 seconds in case instance is shutting down)
