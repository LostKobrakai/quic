defmodule Quic.VersionIndependent.LongHeaderPacket do
  defstruct [
    :addressing_information,
    :version_specific_bits,
    :version,
    :destination_connection_id,
    :source_connection_id,
    :version_specific_data
  ]

  @type t :: %__MODULE__{}

  def parse(<<
        1::1,
        version_specific_bits::bitstring-7,
        version::32,
        destination_connection_id_length::8,
        destination_connection_id::binary-size(destination_connection_id_length),
        source_connection_id_length::8,
        source_connection_id::binary-size(source_connection_id_length),
        rest::binary
      >>) do
    packet = %__MODULE__{
      version_specific_bits: version_specific_bits,
      version: version,
      destination_connection_id: destination_connection_id,
      source_connection_id: source_connection_id,
      version_specific_data: rest
    }

    {:ok, packet}
  end

  def parse(_), do: :error

  def to_binary(%__MODULE__{
        version_specific_bits: version_specific_bits,
        version: version,
        destination_connection_id: destination_connection_id,
        source_connection_id: source_connection_id,
        version_specific_data: version_specific_data
      }) do
    destination_connection_id_length = byte_size(destination_connection_id)
    source_connection_id_length = byte_size(source_connection_id)

    <<
      1::1,
      version_specific_bits::7,
      version::32,
      destination_connection_id_length::8,
      destination_connection_id::binary-size(destination_connection_id_length),
      source_connection_id_length::8,
      source_connection_id::binary-size(source_connection_id_length),
      version_specific_data::binary
    >>
  end
end
