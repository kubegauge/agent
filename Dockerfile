# Dockerfile builds the KubeGauge in-cluster agent: static Go binary + trivy, on distroless.
# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26
ARG TRIVY_VERSION=0.72.0
ARG VERSION=dev

FROM golang:${GO_VERSION} AS build
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/kubegauge-agent ./cmd/kubegauge-agent

FROM ghcr.io/aquasecurity/trivy:${TRIVY_VERSION} AS trivy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/kubegauge-agent /usr/local/bin/kubegauge-agent
# PATH mínimo: exec.LookPath("trivy") do scanner resolve via PATH.
ENV PATH=/usr/local/bin
USER 65532:65532
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/kubegauge-agent"]
