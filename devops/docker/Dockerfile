FROM golang:1.16 as builder

WORKDIR /src

COPY . .

RUN go build -o /bin/stratus .

FROM golang:1.16 as app

COPY --from=builder /bin/stratus /bin/stratus

ENTRYPOINT [ "/bin/stratus" ]
