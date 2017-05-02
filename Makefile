
.PHONY: start test autobahn
start:
	go run main.go frame.go ws.go
test:
	go test
autobahn:
	wstest -m fuzzingclient
