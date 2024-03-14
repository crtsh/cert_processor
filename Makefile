all: clean cert_processor

cert_processor:
	go build -o $@ -ldflags "-X github.com/crtsh/cert_processor/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ`"

clean:
	rm -f cert_processor
