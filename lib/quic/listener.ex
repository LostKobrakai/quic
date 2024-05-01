defmodule Quic.Listener do
  use GenServer
  require Logger

  def start_link(%Quic.Config{} = config) do
    GenServer.start_link(__MODULE__, config)
  end

  @impl GenServer
  def init(%Quic.Config{} = config) do
    {:ok, socket} = :gen_udp.open(config.port, [:binary, active: :once])
    {:ok, %{socket: socket, config: config}}
  end

  @impl GenServer
  def handle_info({:udp, socket, address, port, dataframe}, state) do
    case start_parsing_dataframe(dataframe) do
      {:continue, packet, impl} ->
        port = with 0 <- port, do: :inet.port(socket)
        %{packet | addressing_information: {address, port}}

        Logger.debug(
          "Handing packet over to protocol implementation: #{inspect(impl)} #{inspect(packet)}"
        )

        impl.transfer_handling(state.config, packet)

      {:version_negotiation, packet} ->
        Logger.debug("Sending version negotiation for: #{inspect(packet)}")

      {:discard, bin} when is_binary(bin) ->
        Logger.info("Discarding invalid data: #{inspect(bin)}")
    end

    :inet.setopts(socket, active: :once)
    {:noreply, state}
  end

  # Given RFC8999 short header packets might be used as initial packet at some point,
  # but RFC9000(V1) doesn't allow for that and even RFC8999 acknowledges the need
  # for additional context to be able to parse a short header packet.
  # Therefore this discards everything, which cannot be parsed to RFC8999 long header
  # format.
  #
  # This also doesn't attempt to recursively parse packets, given version specific
  # information is needed to find the end of a packet for coalescing and coalescing
  # is only allowed for matching connection IDs, so the packet can be given to a
  # connection process for finishing parsing.
  @spec start_parsing_dataframe(binary()) ::
          {:discard, binary}
          | {:continue, Quic.VersionIndependent.packet(), Quic.ProtocolVersion.t()}
          | {:version_negotiation, Quic.VersionIndependent.LongHeaderPacket.t()}

  defp start_parsing_dataframe(dataframe) do
    case Quic.VersionIndependent.LongHeaderPacket.parse(dataframe) do
      {:ok, %Quic.VersionIndependent.LongHeaderPacket{} = packet} ->
        check_version(packet.version, packet)

      :error ->
        {:discard, dataframe}
    end
  end

  # Handling version negotiation packets depends on the quic version chosen
  # Supporting just RFC9000(V1) means such packets are only meant to be sent by servers
  # Therefore they are discarded here.
  defp check_version(0, packet) do
    {{:discard, packet}, <<>>}
  end

  defp check_version(version, packet) do
    case Map.fetch(Quic.supported_versions(), version) do
      {:ok, impl} ->
        {:continue, packet, impl}

      :error ->
        # TODO check for size of packet to potentially discard this
        # See RFC9000 5.2.2
        {:version_negotiation, packet}
    end
  end
end
