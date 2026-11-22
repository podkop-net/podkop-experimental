//go:build !race

package subscription

// raceDetector tells a test built with -race (race_test.go).
const raceDetector = false
