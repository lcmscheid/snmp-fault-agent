# Build in the toolchain image, ship on a distroless base: the agent is a static
# binary plus two JSON files, so there is nothing else for the runtime image to
# carry, and a smaller image is one CI pulls faster on every job.
FROM golang:1.24 AS build

WORKDIR /src

# Copy the module files first so dependency download is cached independently of
# the source, which changes far more often.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 is what makes the binary runnable on a base with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/snmpfault .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/snmpfault /usr/local/bin/snmpfault

# The example configuration is baked in so the image runs with no volume mount.
# Override either file by mounting over these paths.
COPY examples/auth.json   /etc/snmpfault/auth.json
COPY examples/values.json /etc/snmpfault/values.json

# 1161 rather than 161: the nonroot user cannot bind a privileged port. Publish
# it wherever the host wants with -p.
EXPOSE 1161/udp
EXPOSE 8080/tcp

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/snmpfault"]
CMD ["-endpoint", "0.0.0.0:1161", \
     "-http", "0.0.0.0:8080", \
     "-auth", "/etc/snmpfault/auth.json", \
     "-values", "/etc/snmpfault/values.json"]
