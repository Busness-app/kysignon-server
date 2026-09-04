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

// Nothing in the server decrypts a capsule. The only caller of recoverykey.Combine and
// capsule.Open outside tests is the restore command, which takes shares from an operator.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := map[string]bool{"Combine": true, "FromSeed": true, "Open": true, "Generate": false}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "web" || name == "node_modules" || strings.HasPrefix(name, ".") && name != "." {
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
		aliases := map[string]string{}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == "github.com/Busness-app/ky-primitives/recoverykey" || p == "github.com/Busness-app/ky-primitives/capsule" {
				name := path[strings.LastIndex(p, "/")+1:]
				name = p[strings.LastIndex(p, "/")+1:]
				if imp.Name != nil {
					name = imp.Name.Name
				}
				aliases[name] = p
			}
		}
		if len(aliases) == 0 {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if _, imported := aliases[id.Name]; !imported {
				return true
			}
			if forbidden[sel.Sel.Name] {
				rel, _ := filepath.Rel(root, path)
				// The restore command is the one legitimate caller: shares typed by an operator.
				if rel == filepath.Join("cmd", "kysignon", "main.go") {
					return true
				}
				t.Errorf("%s: %s.%s reaches a capsule's plaintext", fset.Position(sel.Pos()), id.Name, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
