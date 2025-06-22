FROM golang:1.24.4-alpine AS go_builder

WORKDIR /src
COPY . .

RUN apk update && apk upgrade && apk add --no-cache ca-certificates tzdata
RUN update-ca-certificates
RUN go build -o ./tmp/main

FROM scratch

WORKDIR /src

COPY --from=go_builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=go_builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=go_builder /src/tmp/main /src

ENV TZ Asia/Jakarta

ENTRYPOINT ["./main"]