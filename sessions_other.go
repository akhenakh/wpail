//go:build !linux && !freebsd

package main

// connectionsSupported reports whether the platform backend tracks sessions.
// The macOS libproc backend does not pair sessions yet.
const connectionsSupported = false
