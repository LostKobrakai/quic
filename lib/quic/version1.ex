defmodule Quic.Version1 do
  alias Quic.VersionIndependent

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