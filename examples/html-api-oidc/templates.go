package main

import (
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

type TemplateData struct {
	IsAuthenticated bool
	UserId          string
	Blogs           []Blog
	Blog            *Blog
	CurrentRoute    string
}

var templateCache map[string]*template.Template

func initTemplateCache() error {
	templateCache = make(map[string]*template.Template)

	pages := []string{"index.html", "create.html", "view.html", "login.html"}

	for _, page := range pages {
		pagePath := filepath.Join("templates", page)

		tmpl, err := template.ParseFiles(
			filepath.Join("templates", "base.html"),
			filepath.Join("templates", "partials", "navbar.html"),
			pagePath,
		)
		if err != nil {
			return fmt.Errorf("error parsing template %s: %w", page, err)
		}

		templateCache[page] = tmpl
	}

	return nil
}

func renderTemplate(w http.ResponseWriter, tmpl string, data TemplateData) {
	t, ok := templateCache[tmpl]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	err := t.ExecuteTemplate(w, "layout", data)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}
