build:
	go build -o bin/auth-server bthreader/auth-server/src/main
test:
	go test ./...
run:
	go run bthreader/auth-server/src/main