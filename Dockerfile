FROM golang:alpine AS build
RUN apk add make git
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN make

FROM alpine
COPY --from=build /build/bin/bloodhound /bloodhound/bloodhound
RUN adduser -S -D -H -h /bloodhound bloodhound && chown bloodhound: /bloodhound/bloodhound && chmod +x /bloodhound/bloodhound && mkdir /bones && chmod 777 /bones
USER bloodhound
EXPOSE 25663/tcp
ENTRYPOINT ["/bloodhound/bloodhound"]
