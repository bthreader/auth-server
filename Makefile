build:
	go build -o bin/auth-server bthreader/auth-server/src/main
build_windows:
	GOOS=windows GOARCH=amd64 go build -o bin/auth-server bthreader/auth-server/src/main
test:
	go test ./... | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''
testv:
	go test ./... -v | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''
run:
	go run bthreader/auth-server/src/main
reload:
	$(MAKE) build
	$(MAKE) run
gen_keys:
	mkdir tempkeysdir
	openssl genrsa -out tempkeysdir/private_key.pem 2048
	echo "PRIVATE_KEY=\"$$(base64 tempkeysdir/private_key.pem | tr -d '\n')\"" >> .env
	openssl rsa -in tempkeysdir/private_key.pem -out tempkeysdir/public_key.pem -pubout
	echo "PUBLIC_KEY=\"$$(base64 tempkeysdir/public_key.pem | tr -d '\n')\"" >> .env
	rm -r tempkeysdir
zip:
	zip -r zipped_files.zip .