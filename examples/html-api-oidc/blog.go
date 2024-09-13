package main

import "time"

type Blog struct {
	ID          int
	Title       string
	Author      string
	Excerpt     string
	Content     string
	Tags        []string
	PublishedAt time.Time
}

var blogs = []Blog{
	{
		ID:          1,
		Title:       "Introduction to Go",
		Author:      "John Doe",
		Excerpt:     "Learn the basics of the Go programming language in this introductory blog.",
		Content:     "Lorem ipsum, dolor sit amet consectetur adipisicing elit. Perspiciatis quibusdam, earum assumenda dolorum harum...",
		Tags:        []string{"Go", "Programming", "Basics"},
		PublishedAt: time.Now().AddDate(0, 0, -5),
	},
	{
		ID:          2,
		Title:       "Understanding JWT Authentication",
		Author:      "Jane Smith",
		Excerpt:     "This blog explains what JWTs are and how to use them for authentication in web apps.",
		Content:     "Lorem ipsum, dolor sit amet consectetur adipisicing elit. Perspiciatis quibusdam, earum assumenda dolorum harum...",
		Tags:        []string{"JWT", "Authentication", "Security"},
		PublishedAt: time.Now().AddDate(0, 0, -2),
	},
}
