//go:build race

package subscription

// raceDetector tells a test built with -race, where the race detector slows the code many times
// over: TestBoundsTime then runs its shapes without holding them to its bounds of time.
const raceDetector = true
