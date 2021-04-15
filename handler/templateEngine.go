package handler

import (
	"github.com/eknkc/amber"
	"html/template"
	"os"
)

type DirOptions struct {
}

func Compile(data string) (*template.Template, error) {

	var tpl *template.Template

	compiler := amber.New()
	// Parse the input file
	err := compiler.ParseFile("./public/index.html")
	if err == nil {
		// Compile input file to Go template
		tpl, err = compiler.Compile()
		if err == nil {
			// Check built in html/template documentation for further details
			tpl.Execute(os.Stdout, data)
		}
	}

	return tpl, nil
}
