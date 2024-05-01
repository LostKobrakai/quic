defmodule Quic do
  use Supervisor

  @typedoc "Packet struct related to a specific protocol version"
  @type addressing_information :: {:inet.ip_address(), :inet.port_number()}
  @type protocol_packet :: struct()

  @spec supported_versions() :: %{pos_integer() => Quic.ProtocolVersion.t()}
  def supported_versions do
    %{
      1 => Quic.Version1
    }
  end

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg)
  end

  @impl true
  def init(init_arg) do
    config = Quic.Config.new(init_arg)

    protocol_children = for {_, impl} <- supported_versions(), do: {impl, config}
    children = protocol_children ++ [{Quic.Listener, config}]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
