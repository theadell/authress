package main

import (
	"net/http"

	"github.com/theadell/authress"
)

func SetupRoutes(v *authress.Validator) *http.ServeMux {
	mux := http.NewServeMux()

	// Token extraction from the cookie
	tokenExtractor := authress.WithTokenExtractor(authress.CookieTokenExtractor("access_token"))

	// Redirect to the login page instead of default behaviour of returning 401
	redirectToLoginPage := authress.WithErrorResponder(func(w http.ResponseWriter, r *http.Request, err error) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	// Authentication middleware
	authMiddleware := authress.RequireAuthJWT(v, tokenExtractor, redirectToLoginPage)

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Public routes
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)
	mux.HandleFunc("/logout", logoutHandler)

	// Authenticated routes
	mux.Handle("/", authMiddleware(http.HandlerFunc(homeHandler)))
	mux.Handle("/blog/", authMiddleware(http.HandlerFunc(viewBlogHandler)))
	mux.Handle("/create", authMiddleware(http.HandlerFunc(createPostHandler)))
	mux.Handle("/delete", authMiddleware(http.HandlerFunc(deleteBlogHandler)))

	return mux
}
