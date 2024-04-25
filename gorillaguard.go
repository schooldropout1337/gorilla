package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"strings"
)

var fset *token.FileSet

type Source struct {
	Expr   string
	Line   int
	Column int
}

func main() {
	fset = token.NewFileSet()

	// Get the filename or URL from the user
	fmt.Print("Enter the filename or URL with .go extension to audit: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input:", err)
		os.Exit(1)
	}

	input = strings.TrimSpace(input)

	// Parse the Go source file or download and parse if URL provided
	var node ast.Node
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		// Download the file from the URL
		resp, err := http.Get(input)
		if err != nil {
			fmt.Println("Error downloading file from URL:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Error: HTTP status code", resp.StatusCode)
			os.Exit(1)
		}

		// Parse the downloaded file
		node, err = parser.ParseFile(fset, "downloaded_file.go", resp.Body, parser.ParseComments)
		if err != nil {
			fmt.Println("Error parsing downloaded Go source file:", err)
			os.Exit(1)
		}
	} else {
		// Parse the local file
		node, err = parser.ParseFile(fset, input, nil, parser.ParseComments)
		if err != nil {
			fmt.Println("Error parsing local Go source file:", err)
			os.Exit(1)
		}
	}

	// Function to detect potential path traversal vulnerabilities
	detectPathTraversal := func(node ast.Node) bool {
		// Look for function calls to sessions.NewFilesystemStore
		if callExpr, ok := node.(*ast.CallExpr); ok {
			if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := selExpr.X.(*ast.Ident); ok {
					if ident.Name == "sessions" && selExpr.Sel.Name == "NewFilesystemStore" {
						// Check arguments of NewFilesystemStore
						if len(callExpr.Args) >= 1 {
							// Check if the first argument is derived from user input
							if sources := findSources(callExpr.Args[0]); len(sources) > 0 {
								vulnLine := fset.Position(callExpr.Pos()).Line
								fmt.Printf("\x1b[1;32mPotential path traversal vulnerability detected at line: %d\x1b[0m\n", vulnLine)
								for _, source := range sources {
									fmt.Printf("Source: %s at line %d, column %d\n", source.Expr, source.Line, source.Column)
								}
							}
						}
					}
				}
			}
		}
		return true
	}

	// Traverse the AST to detect potential path traversal vulnerabilities
	ast.Inspect(node, detectPathTraversal)
}

// Function to find sources (user-controlled inputs) in an expression
func findSources(expr ast.Expr) []Source {
	var sources []Source

	// Recursive function to traverse the AST
	var traverseAST func(ast.Node)
	traverseAST = func(node ast.Node) {
		switch n := node.(type) {
		case *ast.Ident:
			// Check if the identifier represents a potential source
			// Example: cookie.Value
			sources = append(sources, Source{Expr: n.Name, Line: fset.Position(n.Pos()).Line, Column: fset.Position(n.Pos()).Column})
		case *ast.SelectorExpr:
			// Check if the selector expression represents a potential source
			// Example: r.URL.Query().Get("param")
			sources = append(sources, Source{Expr: exprToString(n), Line: fset.Position(n.Pos()).Line, Column: fset.Position(n.Pos()).Column})
			// Traverse the AST recursively for the X and Sel nodes
			traverseAST(n.X)
			traverseAST(n.Sel)
		// Add more cases as needed to cover other potential sources of user input
		}
	}

	// Start traversing the AST
	traverseAST(expr)

	return sources
}

// Function to convert an expression to string
func exprToString(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return fmt.Sprintf("%s.%s", exprToString(expr.X), expr.Sel.Name)
		// Add more cases as needed to cover other potential expressions
	default:
		return ""
	}
}

