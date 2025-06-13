FROM golang:1.24.3

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

RUN go build -o /jwe-server

EXPOSE 8888

CMD ["/jwe-server"]
EXPOSE 8888

CMD ["/jwe-server"]
