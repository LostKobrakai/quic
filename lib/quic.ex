defmodule Quic do
  use GenServer
  require Logger

  @typedoc "Packet struct related to a specific protocol version"
  @type protocol_packet :: struct()

  @spec supported_versions() :: %{pos_integer() => Quic.ProtocolVersion.t()}
  def supported_versions do
    %{
      1 => Quic.Version1
    }
  end

  def start_link(init_arg) do
    GenServer.start_link(__MODULE__, init_arg)
  end

  @impl GenServer
  def init(init_arg) do
    port = Keyword.fetch!(init_arg, :port)
    {:ok, socket} = :gen_udp.open(port, [:binary, active: :once])
    {:ok, %{socket: socket}}
  end

  @impl GenServer
  def handle_info({:udp, socket, address, port, dataframe}, state) do
    parts = parse_dataframe(dataframe)
    :inet.setopts(state.socket, active: :once)
    {:noreply, state, {:continue, {:handle_parts, socket, address, port, parts}}}
  end

  @impl GenServer
  def handle_continue({:handle_parts, _socket, _address, _port, []}, state) do
    {:noreply, state}
  end

  def handle_continue({:handle_parts, socket, address, port, [part | rest]}, state) do
    responses =
      case part do
        {:discard, bin} when is_binary(bin) ->
          Logger.info("Discarding invalid data: #{inspect(bin)}")
          []

        {:discard, packet}
        when is_struct(packet, Quic.VersionIndependent.LongHeaderPacket) or
               is_struct(packet, Quic.VersionIndependent.ShortHeaderPacket) ->
          Logger.info(
            "Discarding packet failed to be parsed to a protocol version specific packet: #{inspect(packet)}"
          )

          []

        {:packet, packet} ->
          Logger.error("Implement handling: #{inspect(packet)}")
          []

        {:version_negotiation, packet} ->
          Logger.debug("Sending version negotiation for: #{inspect(packet)}")
          versions = Map.keys(supported_versions())
          [Quic.VersionIndependent.version_negotiation_packet(packet, versions)]
      end

    Logger.error("Sending off: #{inspect(responses)}")
    {:noreply, state, {:continue, {:handle_parts, socket, address, port, rest}}}
  end

  # Given RFC8999 short header packets might be used as initial packet at some point,
  # but RFC9000(V1) doesn't allow for that and even RFC8999 acknowledges the need
  # for additional context to be able to parse a short header packet.
  # Therefore this discards everything, which cannot be parsed to RFC8999 long header
  # format.
  @spec parse_dataframe(binary()) :: [
          {:discard, binary | Quic.VersionIndependent.packet()}
          | {:packet, protocol_packet()}
          | {:version_negotiation, Quic.VersionIndependent.LongHeaderPacket.t()}
        ]
  defp parse_dataframe(remaining, acc \\ [])

  defp parse_dataframe(<<>>, acc), do: Enum.reverse(acc)

  defp parse_dataframe(remaining, acc) do
    case Quic.VersionIndependent.LongHeaderPacket.parse(remaining) do
      {:ok, %Quic.VersionIndependent.LongHeaderPacket{} = packet} ->
        {element, rest} = parse_to_version(packet.version, packet)
        parse_dataframe(rest, [element | acc])

      :error ->
        parse_dataframe(<<>>, [{:discard, remaining} | acc])
    end
  end

  # Handling version negotiation packets depends on the quic version chosen
  # Supporting just RFC9000(V1) means such packets are only meant to be sent by servers
  # Therefore they are discarded here.
  defp parse_to_version(0, packet) do
    {{:discard, packet}, <<>>}
  end

  defp parse_to_version(version, packet) do
    case Map.fetch(supported_versions(), version) do
      {:ok, impl} ->
        case impl.parse_contextless(packet) do
          {:ok, packet, rest} -> {{:packet, packet}, rest}
        end

      :error ->
        # TODO check for size of packet to potentially discard this
        # See RFC9000 5.2.2
        {{:version_negotiation, packet}, <<>>}
    end
  end
end
