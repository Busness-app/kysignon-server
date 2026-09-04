package backup_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowedOpens are the only non-test callers of capsule.Open: the restore command, with
// shares typed by an operator, and the drill, which opens a capsule sealed to a key it
// generated and discards in the same call. recoverykey.Combine and FromSeed are allowed in
// restore alone. No server code opens a capsule sealed to the suite key.
var allowedOpens = map[string]map[string]bool{
	filepath.Join("cmd", "kysignon", "main.go"):     {"Open": true, "Combine": true, "FromSeed": true},
	filepath.Join("internal", "backup", "drill.go"): {"Open": true},
}

var allowedFuncs = map[string]string{
	filepath.Join("cmd", "kysignon", "main.go"):     "restore",
	filepath.Join("internal", "backup", "drill.go"): "RunRestoreDrill",
}

func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"Combine": true, "FromSeed": true, "Open": true}
	fset := token.NewFileSet()
	var seen int
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (d.Name() == "web" || d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		seen++
		aliases := map[string]bool{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "github.com/Busness-app/ky-primitives/recoverykey" || p == "github.com/Busness-app/ky-primitives/capsule" {
				name := p[strings.LastIndex(p, "/")+1:]
				if imp.Name != nil {
					name = imp.Name.Name
				}
				aliases[name] = true
			}
		}
		if len(aliases) == 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		// Function ranges, so a declaration after an exempt function does not inherit it.
		type span struct {
			name     string
			from, to token.Pos
		}
		var funcs []span
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				funcs = append(funcs, span{fn.Name.Name, fn.Pos(), fn.End()})
			}
		}
		enclosing := func(pos token.Pos) string {
			for _, s := range funcs {
				if pos >= s.from && pos <= s.to {
					return s.name
				}
			}
			return ""
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !aliases[id.Name] || !forbidden[sel.Sel.Name] {
				return true
			}
			if allowedOpens[rel][sel.Sel.Name] && enclosing(sel.Pos()) == allowedFuncs[rel] {
				return true
			}
			t.Errorf("%s: %s.%s reaches a capsule's plaintext", fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 10 {
		t.Fatalf("walked only %d Go files; the guard is not looking at the repository", seen)
	}
}
