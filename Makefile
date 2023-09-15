run:
	go run ./cmd/
generate:
	@echo running code generation
	@go generate ./...
	@echo done	