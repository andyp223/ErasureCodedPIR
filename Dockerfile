FROM golang:1.19-alpine

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY . /app
RUN apk add --no-cache g++ make swig openssl-dev
RUN export GO111MODULE=off 
RUN export GOPATH="/app"
