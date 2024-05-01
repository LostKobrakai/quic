defmodule Quic.Version1.TLS do
  @mapping %{
    0x00 => :original_destination_connection_id,
    0x01 => :max_idle_timeout,
    0x02 => :stateless_reset_token,
    0x03 => :max_udp_payload_size,
    0x04 => :initial_max_data,
    0x05 => :initial_max_stream_data_bidi_local,
    0x06 => :initial_max_stream_data_bidi_remote,
    0x07 => :initial_max_stream_data_uni,
    0x08 => :initial_max_streams_bidi,
    0x09 => :initial_max_streams_uni,
    0x0A => :ack_delay_exponent,
    0x0B => :max_ack_delay,
    0x0C => :disable_active_migration,
    0x0D => :preferred_address,
    0x0E => :active_connection_id_limit,
    0x0F => :initial_source_connection_id,
    0x10 => :retry_source_connection_id
  }

  def parse_client_hello(
        <<_::binary-size(34), sid_length::8, _::binary-size(sid_length), cs_length::16,
          _::binary-size(cs_length), cm_length::8, _::binary-size(cm_length),
          extensions::binary>> = client_hello
      ) do
    exts = :ssl_handshake.decode_vector(extensions)
    quic_extensions = extract_quic_transport_parameters(exts) |> IO.inspect()

    tuple = :tls_handshake.decode_handshake(:"tls1.3", 1, client_hello)
    extensions = elem(tuple, 7)
    put_elem(tuple, 7, Map.merge(extensions, quic_extensions))
  end

  def extract_quic_transport_parameters(exts, acc \\ %{})

  def extract_quic_transport_parameters(<<>>, acc) do
    acc
  end

  def extract_quic_transport_parameters(
        <<0x39::16, len::16, data::binary-size(len), rest::binary>>,
        acc
      ) do
    data = parse_quic_transport_parameters(data)
    extract_quic_transport_parameters(rest, Map.merge(acc, %{quic_transport_parameters: data}))
  end

  def extract_quic_transport_parameters(
        <<_::16, len::16, _::binary-size(len), rest::binary>>,
        acc
      ) do
    extract_quic_transport_parameters(rest, acc)
  end

  defp parse_quic_transport_parameters(data) do
    Stream.unfold(data, fn
      <<>> ->
        nil

      rest ->
        {id, rest} = Quic.Version1.Encoding.decode_variable_length_integer(rest)
        {length, rest} = Quic.Version1.Encoding.decode_variable_length_integer(rest)
        <<value::binary-size(length), rest::binary>> = rest
        {{Map.fetch!(@mapping, id), value}, rest}
    end)
    |> Enum.map(fn
      {key, v}
      when key in [
             :max_idle_timeout,
             :initial_max_data,
             :initial_max_stream_data_bidi_local,
             :initial_max_stream_data_bidi_remote,
             :initial_max_stream_data_uni,
             :initial_max_streams_bidi,
             :initial_max_streams_uni
           ] ->
        {key, :binary.decode_unsigned(v)}

      {_, _} = pair ->
        pair
    end)
    |> Map.new()
  end
end
