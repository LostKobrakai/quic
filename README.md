# Quic

Plain elixir based implementation of QUIC (RFC 8999, 9000, 9001).

## Development

QUIC is tls encrypted by default, therefore certificates are required. The repo
currently requires `mkcert` to be installed to handle those certs.

```
# Create certificates
mix setup

# Start development server
mix dev
iex -S mix dev
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `quic` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:quic, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at <https://hexdocs.pm/quic>.

