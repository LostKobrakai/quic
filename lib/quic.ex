defmodule Quic do
  use GenServer

  def start_link(init_arg) do
    GenServer.start_link(__MODULE__, init_arg)
  end

  def init(init_arg) do
    port = Keyword.fetch!(init_arg, :port)
    {:ok, socket} = :gen_udp.open(port, [:binary, active: :once])
    {:ok, %{socket: socket}}
  end

  def handle_info({:udp, _socket, _address, _port, packet}, state) do
    IO.inspect(packet, limit: :infinity)

    with {:ok, %Quic.VersionIndependent.LongHeaderPacket{} = packet} <-
           Quic.VersionIndependent.LongHeaderPacket.parse(packet),
         {:ok, 0x00} <- Quic.Version1.validate_v1_packet(packet),
         {:ok, %Quic.Version1.InitialPacket{} = packet, rest} <-
           Quic.Version1.InitialPacket.from_version_independent(packet) do
      {:ok, packet, rest}
    end
    |> IO.inspect(limit: :infinity)

    :inet.setopts(state.socket, active: :once)
    {:noreply, state}
  end
end
