FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod main.go ./
COPY lists/ lists/
RUN go run .

FROM scratch
COPY --from=builder /build/whitedomains.dat /build/whiteips.dat /build/category-ru.list /build/youtube.list /
COPY --from=builder /build/*.sha256sum /
