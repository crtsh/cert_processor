all: clean cert_processor

cert_processor:
	go build -o $@ -ldflags "$(shell ~/go/bin/govvv -flags | sed 's/main/github.com\/crtsh\/cert_processor\/config/g')"

clean:
	rm -f cert_processor
