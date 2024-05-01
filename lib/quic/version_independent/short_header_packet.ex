defmodule Quic.VersionIndependent.ShortHeaderPacket do
  defstruct [
    :version_specific_bits,
    :destination_connection_id,
    :version_specific_data
  ]

  @type t :: %__MODULE__{}

  def parse(packet, destination_connection_id_length) do
    case packet do
      <<
        0::1,
        version_specific_bits::bitstring-7,
        destination_connection_id::binary-size(destination_connection_id_length),
        rest::binary
      >> ->
        packet = %__MODULE__{
          version_specific_bits: version_specific_bits,
          destination_connection_id: destination_connection_id,
          version_specific_data: rest
        }

        {:ok, packet}

      _ ->
        :error
    end
  end

  def to_binary(%__MODULE__{
        version_specific_bits: version_specific_bits,
        destination_connection_id: destination_connection_id,
        version_specific_data: version_specific_data
      }) do
    destination_connection_id_length = byte_size(destination_connection_id)

    <<
      0::1,
      version_specific_bits::7,
      destination_connection_id::binary-size(destination_connection_id_length),
      version_specific_data::binary
    >>
  end
end
