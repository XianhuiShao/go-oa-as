# Specifies a parent image
FROM golang:1.20-alpine

#为镜像设置必要的环境变量
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Creates an app directory to hold your app’s source code
WORKDIR /root/go/go-api-ftp

# Copies everything from your root directory into /app
#COPY . /root/go/go-api-ftp
COPY go.mod go.sum ./

# Installs Go dependencies
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY *.go ./

# Builds your app with optional configuration
RUN go build -o /go-api-ftp

# Tells Docker which network port your container listens on
EXPOSE 50016

# Specifies the executable command that runs when the container starts
CMD [ "/go-api-ftp" ]