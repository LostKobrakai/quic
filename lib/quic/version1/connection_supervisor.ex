defmodule Quic.Version1.ConnectionSupervisor do
  use DynamicSupervisor

  def start_link(%Quic.Config{} = config) do
    DynamicSupervisor.start_link(__MODULE__, config, name: via(config))
  end

  @impl true
  def init(_init_arg) do
    DynamicSupervisor.init(strategy: :one_for_one)
  end

  @spec start_connection(Quic.Config.t(), Quic.VersionIndependent.LongHeaderPacket.t()) ::
          DynamicSupervisor.on_start_child()
  def start_connection(%Quic.Config{} = config, packet) do
    DynamicSupervisor.start_child(
      via(config),
      {Quic.Version1.Connection,
       {config, packet.addressing_information, packet.destination_connection_id}}
    )
  end

  defp via(config) do
    Quic.Registry.via(config, __MODULE__)
  end
end
