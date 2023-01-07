build:
	go build -o bin/auth-server bthreader/auth-server/src/main
test:
	go test ./...