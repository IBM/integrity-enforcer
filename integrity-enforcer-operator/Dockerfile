# Build
# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
ADD /resources/default-rsp.yaml /resources/default-rsp.yaml
ADD /resources/default-ie-cr.yaml /resources/default-ie-cr.yaml

WORKDIR /
COPY build/_output/bin/integrity-enforcer-operator manager
USER nonroot:nonroot

ENTRYPOINT ["/manager"]