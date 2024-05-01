defmodule Quic.ProtocolVersion do
  alias Quic.VersionIndependent

  @type t :: module()

  @callback parse_contextless(
              VersionIndependent.LongHeaderPacket.t()
              | VersionIndependent.ShortHeaderPacket.t()
            ) :: {:ok, Quic.protocol_packet(), rest :: binary()}
end
