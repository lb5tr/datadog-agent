package profiling

import "time"

// Settings contains the settings for internal profiling, to be passed to Start().
type Settings struct {
	// Site specifies the datadog site (datadoghq.com, datadoghq.eu, etc.) which profiles will be sent to.
	Site string
	// Env specifies the environment to which profiles should be registered.
	Env string
	// Service specifies the service name to attach to a profile.
	Service string
	// Period specifies the interval at which to collect profiles.
	Period time.Duration
	// CPUDuration specifies the length at which to collect CPU profiles.
	CPUDuration time.Duration
	// MutexProfileFraction, if set, turns on mutex profiles with rate
	// indicating the fraction of mutex contention events reported in the mutex
	// profile.
	MutexProfileFraction int
	// BlockProfileRate turns on block profiles with the given rate.
	BlockProfileRate int
	// WithGoroutineProfile additionally reports stack traces of all current goroutines
	WithGoroutineProfile bool
	// Tags are the additional tags to attach to profiles.
	Tags []string
}
