defmodule Quic.Version1 do
  use Supervisor
  alias Quic.VersionIndependent

  @behaviour Quic.ProtocolVersion

  def start_link(%Quic.Config{} = config) do
    Supervisor.start_link(__MODULE__, config)
  end

  @impl Supervisor
  def init(%Quic.Config{} = config) do
    children = [
      {Quic.Version1.ConnectionSupervisor, config}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  @impl Quic.ProtocolVersion
  def transfer_handling(%Quic.Config{} = config, %VersionIndependent.LongHeaderPacket{} = packet) do
    case Quic.Version1.ConnectionSupervisor.start_connection(config, packet) do
      {:ok, pid} when is_pid(pid) -> :ok
      {:error, {:already_started, pid}} when is_pid(pid) -> :ok
    end

    Quic.Version1.Connection.process_packet(config, packet.destination_connection_id, packet)
  rescue
    _ ->
      # TODO log exception
      :ok
  end

  def parse_contextless(%VersionIndependent.LongHeaderPacket{} = packet) do
    case Quic.Version1.validate_v1_packet(packet) do
      {:ok, packet_type} ->
        case packet_type do
          0x00 -> Quic.Version1.InitialPacket.from_version_independent(packet)
        end

      {:error, _kind} ->
        raise "handle"
    end
  end

  def validate_v1_packet(%VersionIndependent.LongHeaderPacket{} = packet) do
    <<fixed_bit::1, long_packet_type::2, _::4>> = packet.version_specific_bits

    cond do
      byte_size(packet.destination_connection_id) > 20 ->
        {:error, :to_large_destination_connection_id}

      byte_size(packet.source_connection_id) > 20 ->
        {:error, :to_large_destination_connection_id}

      packet.version != 1 ->
        {:error, :not_version_1}

      fixed_bit != 1 ->
        {:error, :invalid_fixed_bit}

      long_packet_type not in 0x00..0x03 ->
        {:error, :invalid_long_packet_type}

      true ->
        {:ok, long_packet_type}
    end
  end
end
