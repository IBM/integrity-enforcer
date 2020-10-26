# Build the manager binary
FROM golang:1.13 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY enforcer/go.mod /enforcer/go.mod
COPY enforcer/go.sum /enforcer/go.sum
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download



# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/

# Build
#RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go
COPY build/_output/bin/ie-operator manager
# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
ADD /resources/default-rsp.yaml /resources/default-rsp.yaml

WORKDIR /
COPY --from=builder /workspace/manager . 
USER nonroot:nonroot

ENTRYPOINT ["/manager"]
