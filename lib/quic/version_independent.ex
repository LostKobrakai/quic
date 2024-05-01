defmodule Quic.VersionIndependent do
  alias Quic.VersionIndependent.LongHeaderPacket

  def version_negotiation_packet(%LongHeaderPacket{} = cause, supported)
      when cause.version != 0 do
    %LongHeaderPacket{
      version_specific_bits: 0,
      version: 0,
      destination_connection_id: cause.source_connection_id,
      source_connection_id: cause.destination_connection_id,
      version_specific_data: Enum.map_join(supported, "", fn version -> <<version::32>> end)
    }
  end
end
