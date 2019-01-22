FROM golang:1.10

ENV LOG_LEVEL 'info'
ENV LISTEN_PORT '3000'
ENV LISTEN_ADDRESS '0.0.0.0'

ADD /main.dep $GOPATH/src/jaeger-remote/main.go
RUN go get -v jaeger-remote

ADD jaeger-remote $GOPATH/src/jaeger-remote
RUN go get -v jaeger-remote

ADD startup.sh /

EXPOSE 3000

CMD [ "/startup.sh" ]