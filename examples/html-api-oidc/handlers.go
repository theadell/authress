package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/theadell/authress"
	"golang.org/x/oauth2"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "login.html", TemplateData{})
	} else if r.Method == http.MethodPost {
		state := oauth2.GenerateVerifier()
		url := oauth2Client.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code in request", http.StatusBadRequest)
		return
	}

	token, err := oauth2Client.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusBadRequest)
		return
	}

	idToken, err := validator.ValidateJWT(rawIDToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	accessToken := token.AccessToken

	// Do something with the ID token... The ID token usually contains more detailed user information (e.g., name, email).
	// You might want to use this information to create or update a user record in your database, or store
	// user-specific information in a session store (e.g., user profile, roles).
	// The "sub" claim (subject) in the ID token uniquely identifies the user, and this can be related to
	// user information in your session or database.
	sessionStore.Set(idToken.Subject, &idToken.Claims)

	// After validating the ID token and storing user info (e.g., name, email) in the session, we can use the "sub"
	// claim from the access token to associate it with a primary ID in our database or session store (e.g., Redis),
	// without exposing detailed user data in the token itself.
	//
	// NOTE: This is for demonstration purposes only. In server-side rendering (like Go templates), you should use session-based
	// authentication with a session ID in a secure, HTTP-only cookie and store session data server-side (e.g., Redis).
	StoreTokenInCookie(w, accessToken)

	// Redirect to the home page after successful login
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {

	// authCtx contains the user info contained in the access token
	authCtx, _ := authress.GetAuthCtx(r.Context())

	data := TemplateData{
		IsAuthenticated: authCtx.IsAuthenticated,
		Blogs:           blogs,
		UserId:          authCtx.Token.Subject,
	}
	renderTemplate(w, "index.html", data)

}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		createFormGet(w, r)
	case http.MethodPost:
		createFormPost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func createFormGet(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "create.html", TemplateData{IsAuthenticated: true})
}

func createFormPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusMethodNotAllowed)
		return
	}

	title := r.FormValue("title")
	author := r.FormValue("author")
	excerpt := r.FormValue("excerpt")
	content := r.FormValue("content")
	tagsStr := r.FormValue("tags")

	tags := strings.Split(tagsStr, ",")

	blog := Blog{
		ID:          len(blogs) + 1,
		Title:       title,
		Author:      author,
		Excerpt:     excerpt,
		Content:     content,
		Tags:        tags,
		PublishedAt: time.Now(),
	}

	blogs = append(blogs, blog)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deleteBlogHandler(w http.ResponseWriter, r *http.Request) {

	if len(blogs) > 0 {
		blogs = blogs[1:]
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "access_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func viewBlogHandler(w http.ResponseWriter, r *http.Request) {

	idStr := strings.TrimPrefix(r.URL.Path, "/blog/")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "Invalid blog ID", http.StatusBadRequest)
		return
	}

	var blog *Blog
	for _, b := range blogs {
		if b.ID == id {
			blog = &b
			break
		}
	}

	if blog == nil {
		http.Error(w, "Blog not found", http.StatusNotFound)
		return
	}
	authCtx, _ := authress.GetAuthCtx(r.Context())

	tmplData := TemplateData{
		IsAuthenticated: authCtx.IsAuthenticated,
		Blog:            blog,
		UserId:          authCtx.Token.Subject,
	}
	renderTemplate(w, "view.html", tmplData)
}
