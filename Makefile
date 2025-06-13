.PHONY: build
build: 
	@go generate
	@go build -o hive
