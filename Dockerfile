FROM golang:1-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o server .

FROM alpine:3.20
WORKDIR /app
COPY --from=build /app/server .
COPY certs/ certs/
COPY pass.pass/ pass.pass/
EXPOSE 8080
CMD ["./server"]
