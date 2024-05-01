defmodule Quic.Version1.InitialPacket do
  alias Quic.Version1.Encoding
  alias Quic.Version1.Secret

  defstruct [
    :reserved,
    :destination_connection_id,
    :source_connection_id,
    :token,
    :length,
    :packet_number_length,
    :packet_number,
    :payload
  ]

  alias Quic.VersionIndependent

  def from_version_independent(%VersionIndependent.LongHeaderPacket{} = packet) do
    {token_length, rest} = Encoding.decode_variable_length_integer(packet.version_specific_data)
    <<token::binary-size(token_length), rest::binary>> = rest
    {length, rest} = Encoding.decode_variable_length_integer(rest)

    {version_specific_bits, rest} =
      unprotect_header(packet.destination_connection_id, packet.version_specific_bits, rest)

    <<1::1, 0::2, reserved::2, packet_number_length::2>> = version_specific_bits
    <<packet_number::size(packet_number_length + 1)-unit(8), protected_payload::binary>> = rest

    header_packet = %__MODULE__{
      reserved: reserved,
      destination_connection_id: packet.destination_connection_id,
      source_connection_id: packet.source_connection_id,
      token: token,
      length: length,
      packet_number_length: packet_number_length,
      packet_number: packet_number,
      payload: <<>>
    }

    {:ok, payload, coalesced_packets} = unprotect_payload(header_packet, protected_payload)

    unpad_payload(payload)

    {:ok, %__MODULE__{header_packet | payload: payload}, coalesced_packets}
  end

  def to_binary(%__MODULE__{
        reserved: reserved,
        destination_connection_id: destination_connection_id,
        source_connection_id: source_connection_id,
        token: token,
        length: length,
        packet_number_length: packet_number_length,
        packet_number: packet_number,
        payload: payload
      }) do
    packet_number = <<packet_number::size(packet_number_length + 1)-unit(8)>>

    destination_connection_id_length = byte_size(destination_connection_id)
    source_connection_id_length = byte_size(source_connection_id)

    token_length = Encoding.encode_variable_length_integer(byte_size(token))

    length_value = Encoding.encode_variable_length_integer(length)
    length_length = byte_size(length_value)

    <<
      # long header
      1::1,
      # fixed bit
      1::1,
      # packet number
      0::2,
      reserved::2,
      packet_number_length::2,
      # version
      1::32,
      destination_connection_id_length::8,
      destination_connection_id::binary-size(destination_connection_id_length),
      source_connection_id_length::8,
      source_connection_id::binary-size(source_connection_id_length),
      token_length::binary,
      token::binary,
      length_value::binary-size(length_length),
      packet_number::binary,
      payload::binary
    >>
  end

  defp get_sample(packet_number_and_payload) do
    <<_::binary-size(4), sample::binary-size(16), _::binary>> = packet_number_and_payload
    sample
  end

  # Reconsider hardcoded 32 bit for package_number
  defp unprotect_header(connection_id, version_specific_bits, rest) do
    sample = get_sample(rest)
    initial_secret = Secret.initial_secret(connection_id)
    initial_client_secret = Secret.client_initial_secret(initial_secret)
    hp_key = Secret.header_protection_key(initial_client_secret)

    <<_::bitstring-4, mask_bits::4, mask_packet_number::32>> =
      Secret.mask(hp_key, sample)

    <<first_byte::8>> = <<1::1, version_specific_bits::bitstring>>
    unprotected_first_byte = Bitwise.bxor(first_byte, mask_bits)

    <<1::1, unprotected_version_specific_bits::bitstring-7>> =
      <<unprotected_first_byte::8>>

    # Unprotect using max packet_number size of 4 bytes
    <<packet_number::4*8, _rest::binary>> = rest
    unprotected_packet_number = Bitwise.bxor(packet_number, mask_packet_number)

    # Properly stitch together unprotected packet number without affecting the rest of the payload
    <<_::5, packet_number_length::2>> = unprotected_version_specific_bits
    packet_number_bits = (packet_number_length + 1) * 8

    <<actual_packet_number::size(packet_number_bits), _::binary>> =
      <<unprotected_packet_number::32>>

    <<_::size(packet_number_bits), actual_rest::binary>> = rest

    {
      unprotected_version_specific_bits,
      <<actual_packet_number::size(packet_number_bits), actual_rest::binary>>
    }
  end

  defp unpad_payload(payload) when is_binary(payload) do
    payload
    |> Stream.unfold(fn
      "" ->
        nil

      rest ->
        {frame_type, rest} = Encoding.decode_variable_length_integer(rest)

        {frame_contents, rest} =
          case frame_type do
            0x00 -> {<<>>, rest}
            0x06 -> decode_frame(:crypto, rest)
          end

        {[<<frame_type::8>>, frame_contents], rest}
    end)
    |> Enum.to_list()
  end

  defp decode_frame(:crypto, rest) do
    {_offset, rest} = Encoding.decode_variable_length_integer(rest)
    {length, rest} = Encoding.decode_variable_length_integer(rest)
    <<crypto::binary-size(length), rest::binary>> = rest

    {crypto, rest}
  end

  def unprotect_payload(header_packet, protocted_payload) do
    initial_secret = Secret.initial_secret(header_packet.destination_connection_id)
    initial_client_secret = Secret.client_initial_secret(initial_secret)
    key = Secret.key(initial_client_secret)

    <<iv::96>> = Secret.iv(initial_client_secret)
    nonce = <<Bitwise.bxor(header_packet.packet_number, iv)::96>>

    payload_length = header_packet.length - (header_packet.packet_number_length + 1) - 16

    <<
      payload::binary-size(payload_length),
      tag::binary-size(16),
      coalesced_packets::binary
    >> = protocted_payload

    header = to_binary(header_packet)

    case :crypto.crypto_one_time_aead(:aes_128_gcm, key, nonce, payload, header, tag, false) do
      unprotected when is_binary(unprotected) -> {:ok, unprotected, coalesced_packets}
      :error -> :error
    end
  end
end
