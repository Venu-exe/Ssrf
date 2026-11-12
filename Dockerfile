# Docker image for ssrf_oob.sh -- everything preinstalled.
#
# Build:  docker build -t ssrf-oob .
# Run:    docker run --rm ssrf-oob -u "https://target.com/fetch?url=FUZZ" -o /out
#         (mount -v $PWD:/out to collect results on the host)
FROM golang:1.24-alpine AS build
RUN go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

FROM alpine:3.21
RUN apk add --no-cache bash curl jq git ca-certificates
COPY --from=build /go/bin/interactsh-client /usr/local/bin/interactsh-client
WORKDIR /app
COPY ssrf_oob.sh /usr/local/bin/ssrf_oob.sh
COPY wordlists /app/wordlists
RUN chmod +x /usr/local/bin/ssrf_oob.sh \
    && mkdir -p /usr/local/bin/wordlists \
    && cp /app/wordlists/params.txt /usr/local/bin/wordlists/params.txt
ENTRYPOINT ["/usr/local/bin/ssrf_oob.sh"]
CMD ["--help"]
