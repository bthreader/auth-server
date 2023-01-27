build:
	go build -o bin/auth-server bthreader/auth-server/src/main
test:
	go test ./... | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''
testv:
	go test ./... -v | sed ''/FAIL/s//$$(printf "\033[31mFAIL\033[0m")/''
run:
	go run bthreader/auth-server/src/main
reload:
	$(MAKE) build
	$(MAKE) run
tunnel:
	cloudflared tunnel run dev
serve_html:
	cd src/handlers/ && python3 -m http.server
gen_keys:
	mkdir keys
	openssl genrsa -out keys/private_key.pem 2048
	echo "PRIVATE_KEY=\"$$(base64 keys/private_key.pem | tr -d '\n')\"" >> .env
	openssl rsa -in keys/private_key.pem -out keys/public_key.pem -pubout
	echo "PUBLIC_KEY=\"$$(base64 keys/public_key.pem | tr -d '\n')\"" >> .env
	rm -r keys