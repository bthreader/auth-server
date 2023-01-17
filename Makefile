build:
	go build -o bin/auth-server bthreader/auth-server/src/main
test:
	go test ./... | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''
testv:
	go test ./... -v | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''
run:
	go run bthreader/auth-server/src/main
gen_keys:
	mkdir keys
	$(MAKE) rotate_keys
rotate_keys:
	openssl genrsa -out keys/private_key.pem 2048;
	openssl rsa -in keys/private_key.pem -out keys/public_key.pem