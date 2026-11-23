// testsum reads the output of go test -json and tells what a reader of a CI log needs: the result
// of each package, the output of each test that failed and of each package that did not build or
// ended without its tests' results, and the tests that were skipped, with their reasons. When
// GITHUB_STEP_SUMMARY names a file, the counts and the skipped tests are appended to it as
// Markdown.
//
//	go test -json ... > test.json; go run testsum.go -title TITLE [-allow RE] [-forbid RE] < test.json
//
// A skipped test is matched as "package.Test: reason". -allow RE: every skipped test must match RE
// (a job that runs the tests of the kernel fails when one skips for lack of root, nft or ip);
// -forbid RE: no skipped test may match RE. The exit status is 1 when a test or a package failed
// or a skip broke -allow or -forbid, 2 when the input could not be read. Only the standard library:
// it runs as a file of its own (go run), outside the module of the backend.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

type event struct {
	Action      string
	Package     string
	Test        string
	Elapsed     float64
	Output      string
	ImportPath  string
	FailedBuild string
}

type skip struct{ pkg, test, reason string }

func main() {
	title := flag.String("title", "go test", "the heading of the summary")
	allow := flag.String("allow", "", "every skipped test must match this regular expression")
	forbid := flag.String("forbid", "", "no skipped test may match this regular expression")
	flag.Parse()
	var allowRE, forbidRE *regexp.Regexp
	if *allow != "" {
		allowRE = regexp.MustCompile(*allow)
	}
	if *forbid != "" {
		forbidRE = regexp.MustCompile(*forbid)
	}

	output := map[string][]string{} // package + "\x00" + test (empty: the package's own lines)
	build := map[string][]string{}  // the build output of an import path
	ended := map[string]bool{}      // a test (package + "\x00" + test) with a result
	running := map[string][]string{}
	var skips []skip
	var passed, failed, skipped, packages, failedPackages int

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			var e event
			if json.Unmarshal([]byte(line), &e) != nil || e.Action == "" {
				fmt.Print(line) // not an event: a message of go test itself
			} else {
				key := e.Package + "\x00" + e.Test
				switch {
				case e.Action == "build-output":
					build[e.ImportPath] = append(build[e.ImportPath], e.Output)
				case e.Action == "build-fail":
				case e.Action == "output":
					output[key] = append(output[key], e.Output)
				case e.Action == "run" && e.Test != "":
					running[e.Package] = append(running[e.Package], e.Test)
				case e.Test != "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip"):
					ended[key] = true
					switch e.Action {
					case "pass":
						passed++
					case "fail":
						failed++
						fmt.Print(strings.Join(output[key], ""))
					case "skip":
						skipped++
						skips = append(skips, skip{e.Package, e.Test, reason(output[key])})
					}
					delete(output, key)
				case e.Test == "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip"):
					packages++
					own := output[key]
					delete(output, key)
					switch e.Action {
					case "pass":
						fmt.Printf("ok   %s %.1fs\n", e.Package, e.Elapsed)
					case "skip":
						fmt.Printf("?    %s [no test files]\n", e.Package)
					case "fail":
						failedPackages++
						if e.FailedBuild != "" {
							fmt.Print(strings.Join(build[e.FailedBuild], ""))
						}
						// a test that never ended (a panic, a timeout) has its lines told here
						for _, test := range running[e.Package] {
							k := e.Package + "\x00" + test
							if !ended[k] && len(output[k]) > 0 {
								fmt.Print(strings.Join(output[k], ""))
							}
						}
						fmt.Print(strings.Join(own, ""))
						fmt.Printf("FAIL %s %.1fs\n", e.Package, e.Elapsed)
					}
					delete(running, e.Package)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "testsum:", err)
			os.Exit(2)
		}
	}

	status := 0
	if failed > 0 || failedPackages > 0 {
		status = 1
	}
	sort.Slice(skips, func(i, j int) bool {
		if skips[i].pkg != skips[j].pkg {
			return skips[i].pkg < skips[j].pkg
		}
		return skips[i].test < skips[j].test
	})
	var broken []string
	for _, s := range skips {
		text := short(s.pkg) + "." + s.test + ": " + s.reason
		if (allowRE != nil && !allowRE.MatchString(text)) || (forbidRE != nil && forbidRE.MatchString(text)) {
			broken = append(broken, text)
		}
	}

	counts := fmt.Sprintf("%d packages (%d failed); tests and subtests: %d passed, %d failed, %d skipped",
		packages, failedPackages, passed, failed, skipped)
	fmt.Printf("\n%s: %s\n", *title, counts)
	for _, s := range skips {
		fmt.Printf("SKIP %s.%s: %s\n", short(s.pkg), s.test, s.reason)
	}
	for _, text := range broken {
		fmt.Printf("::error::%s: skipped where it must run: %s\n", *title, text)
		status = 1
	}

	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		var b strings.Builder
		mark := "passed"
		if status != 0 {
			mark = "FAILED"
		}
		fmt.Fprintf(&b, "### %s: %s\n\n%s\n\n", *title, mark, counts)
		if len(skips) > 0 {
			b.WriteString("| Skipped | Reason |\n|---|---|\n")
			for _, s := range skips {
				fmt.Fprintf(&b, "| `%s.%s` | %s |\n", short(s.pkg), s.test, strings.ReplaceAll(s.reason, "|", "\\|"))
			}
			b.WriteString("\n")
		}
		for _, text := range broken {
			fmt.Fprintf(&b, "- skipped where it must run: %s\n", text)
		}
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, err = file.WriteString(b.String())
			file.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "testsum:", err)
		}
	}
	os.Exit(status)
}

// reason is what a skipped test said: its lines but those go test writes itself.
func reason(lines []string) string {
	var said []string
	for _, line := range lines {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "=== ") || strings.HasPrefix(text, "--- SKIP") {
			continue
		}
		said = append(said, text)
	}
	if len(said) == 0 {
		return "(no reason given)"
	}
	return strings.Join(said, " / ")
}

// short drops the module path of the backend from a package's path.
func short(pkg string) string {
	const module = "github.com/podkop-net/podkop-experimental/src/backend"
	if pkg == module {
		return "."
	}
	if rest, ok := strings.CutPrefix(pkg, module+"/"); ok {
		return rest
	}
	return pkg
}
