package podkop

import (
	"bufio"
	"flag"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The packages of the backend import one another along the edges listed in edgesFile, and along
// no other: a new edge fails, and so does a listed edge that the sources no longer have. A move
// between the packages changes the list in the same commit, so that the list stays the graph of
// the backend as it is, and an edge across the layers is a line someone added on purpose. The
// edges are those of the files that are not tests, whatever their build constraints (an edge of
// the lab build or of one system is an edge all the same); testdata is not read. The note of a
// line ("# known: ...") says why an edge is a layering problem already found, so that the commit
// that removes it takes the line out with its note.
//
// go test -run TestImportEdges -update . writes the list anew from the sources, with the notes of
// the edges that stay and the head of the file as they are.
var updateEdges = flag.Bool("update", false, "write "+edgesFile+" anew from the import edges of the sources")

const edgesFile = "testdata/import-edges.txt"

func TestImportEdges(t *testing.T) {
	module := modulePath(t)
	found := make(map[string][]string)
	files := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		files++
		from := filepath.ToSlash(filepath.Dir(path))
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			to, own := ownPackage(imported, module)
			if !own {
				continue
			}
			edge := from + " -> " + to
			if !slices.Contains(found[edge], path) {
				found[edge] = append(found[edge], filepath.ToSlash(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 || len(found) < 50 {
		t.Fatalf("only %d files and %d edges were read: the test does not look where the backend is", files, len(found))
	}
	head, listed := readEdges(t)
	if *updateEdges {
		writeEdges(t, head, listed, found)
		return
	}
	for _, edge := range slices.Sorted(maps.Keys(found)) {
		if _, known := listed[edge]; !known {
			from, to, _ := strings.Cut(edge, " -> ")
			t.Errorf("%s now imports %s: %s; a new edge between the packages: if the layers allow it, add the line %q to %s", from, to, strings.Join(found[edge], ", "), edge, edgesFile)
		}
	}
	for _, edge := range slices.Sorted(maps.Keys(listed)) {
		if _, seen := found[edge]; !seen {
			from, to, _ := strings.Cut(edge, " -> ")
			t.Errorf("%s no longer imports %s: take the line %q out of %s", from, to, edge, edgesFile)
		}
	}
	known := 0
	for _, note := range listed {
		if strings.HasPrefix(note, "known:") {
			known++
		}
	}
	t.Logf("%d edges between the packages, %d of them known layering problems", len(found), known)
}

// modulePath is the path of the module of the backend, from its go.mod.
func modulePath(t *testing.T) string {
	content, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		if path, found := strings.CutPrefix(strings.TrimSpace(line), "module "); found {
			return strings.TrimSpace(path)
		}
	}
	t.Fatal("go.mod names no module")
	return ""
}

// ownPackage is the directory of an imported package of the module, "." for its root package
// (podkop); false for a package of another module.
func ownPackage(imported string, module string) (string, bool) {
	if imported == module {
		return ".", true
	}
	if rest, found := strings.CutPrefix(imported, module+"/"); found {
		return rest, true
	}
	return "", false
}

// readEdges reads edgesFile: the lines of comments before its first edge (its head), and each
// edge with its note. An edge is a line "from -> to", the directories of the packages under
// src/backend, with a note after a "#" or none.
func readEdges(t *testing.T) ([]string, map[string]string) {
	file, err := os.Open(edgesFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var head []string
	listed := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for number := 1; scanner.Scan(); number++ {
		line := scanner.Text()
		text, note, _ := strings.Cut(line, "#")
		text = strings.TrimSpace(text)
		if text == "" {
			if len(listed) == 0 {
				head = append(head, line)
			}
			continue
		}
		from, to, found := strings.Cut(text, " -> ")
		if !found || strings.ContainsAny(from, " \t") || strings.ContainsAny(to, " \t") || from == "" || to == "" {
			t.Fatalf("%s:%d: %q is no edge \"from -> to\"", edgesFile, number, line)
		}
		edge := from + " -> " + to
		if _, twice := listed[edge]; twice {
			t.Fatalf("%s:%d: %s is listed twice", edgesFile, number, edge)
		}
		listed[edge] = strings.TrimSpace(note)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return head, listed
}

// writeEdges writes edgesFile with the edges found, sorted, the notes of those listed before, and
// the head as it was.
func writeEdges(t *testing.T, head []string, listed map[string]string, found map[string][]string) {
	var text strings.Builder
	for _, line := range head {
		text.WriteString(line + "\n")
	}
	for _, edge := range slices.Sorted(maps.Keys(found)) {
		text.WriteString(edge)
		if note := listed[edge]; note != "" {
			text.WriteString(strings.Repeat(" ", max(2, 28-len(edge))) + "# " + note)
		}
		text.WriteString("\n")
	}
	if err := os.WriteFile(edgesFile, []byte(text.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s written: %d edges", edgesFile, len(found))
}
