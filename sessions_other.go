//go:build !linux

package main

// connectionsSupported reports whether the platform backend tracks sessions.
// Only the procfs backend implements session pairing for now.
const connectionsSupported = false
