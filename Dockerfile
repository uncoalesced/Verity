# Verity MCP server as a container (used by Glama, Smithery and the MCP registry OCI package).
# Engineered by uncoalesced
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin verity

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/uncoalesced/Verity" \
      org.opencontainers.image.description="Verity: deterministic accounts-payable auditor (MCP server)" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.uncoalesced/verity"
COPY --from=build /src/target/release/verity /usr/local/bin/verity
USER nonroot
ENTRYPOINT ["/usr/local/bin/verity"]
CMD ["mcp"]