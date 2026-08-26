package mlkembraid

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestDecaps_ZeroizesTheDecapsulationKey is the source-level half of the #24
// site-2 fix. The plain-heap seed copy that kem.NewSecretKey holds inside
// Decaps is not observable from outside the function — sk is a local, its buffer
// is unexported, and GC makes heap residency unmeasurable — so a test that only
// calls Decaps and checks the shared secret (the round-trip tests do that)
// proves nothing about whether the key is bounded.
//
// This asserts the property directly on the source: Decaps must defer
// sk.Zeroize(). It is mutation-verifiable — delete the defer in
// kem_interface.go and this test fails, which is exactly what a test of a
// not-otherwise-observable property has to do to be worth keeping.
func TestDecaps_ZeroizesTheDecapsulationKey(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "kem_interface.go", nil, 0)
	if err != nil {
		t.Fatalf("parse kem_interface.go: %v", err)
	}

	decaps := findMethod(file, "MLKEM768IncrementalKEM", "Decaps")
	if decaps == nil {
		t.Fatal("could not find method (*MLKEM768IncrementalKEM).Decaps in kem_interface.go")
	}

	if !defersCall(decaps, "sk", "Zeroize") {
		t.Error("Decaps must `defer sk.Zeroize()` so the plain-heap decapsulation-key " +
			"copy kem.NewSecretKey holds is bounded to the call rather than resident " +
			"until GC (issue #24 site 2)")
	}
}

// findMethod returns the FuncDecl for the named method on the named receiver
// type, or nil if it is absent.
func findMethod(file *ast.File, recvType, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != name {
			continue
		}
		if receiverTypeName(fn.Recv) == recvType {
			return fn
		}
	}
	return nil
}

// receiverTypeName returns the bare type name of a method receiver, unwrapping a
// pointer receiver, or "" if the shape is unrecognized.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) != 1 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// defersCall reports whether fn's body contains a TOP-LEVEL `defer
// recv.method()` statement. It deliberately does not descend into nested
// closures or blocks: a defer buried in a closure that Decaps never invokes
// would not bound the key, so only a defer in the function body itself counts.
func defersCall(fn *ast.FuncDecl, recv, method string) bool {
	if fn.Body == nil {
		return false
	}
	for _, stmt := range fn.Body.List {
		deferStmt, ok := stmt.(*ast.DeferStmt)
		if !ok {
			continue
		}
		sel, ok := deferStmt.Call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			continue
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == recv {
			return true
		}
	}
	return false
}
