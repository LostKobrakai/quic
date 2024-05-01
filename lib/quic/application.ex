defmodule Quic.Application do
  use Application

  def start(_type, _args) do
    children = [
      Quic.Registry
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Quic.Supervisor)
  end
end
