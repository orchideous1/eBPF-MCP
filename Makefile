test:
	go test ./...

test-nfs-e2e:
	sudo -E go test -count=1 ./test/integration -run TestNFSProbeLoadAndDuckDBIngestionE2E -v

test-race:
	go test -race ./...

vet:
	go vet ./...

clean-testcache:
	go clean -testcache
	rm -rf ./log/**


