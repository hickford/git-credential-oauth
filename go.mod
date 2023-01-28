module github.com/hickford/git-credential-oauth

go 1.19

require golang.org/x/oauth2 v0.0.0-20221006150949-b44042a4b9c1

require (
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.5.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

replace golang.org/x/oauth2 => github.com/hickford/oauth2 v0.0.0-20230128150213-b582cc095f5c
