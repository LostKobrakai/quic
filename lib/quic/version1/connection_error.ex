defmodule Quic.Version1.ConnectionError do
  defexception [:value, :code, :message]

  quic_errors = %{
    0x00 => {"NO_ERROR", "No error"},
    0x01 => {"INTERNAL_ERROR", "Implementation error"},
    0x02 => {"CONNECTION_REFUSED", "Server refuses a connection"},
    0x03 => {"FLOW_CONTROL_ERROR", "Flow control error"},
    0x04 => {"STREAM_LIMIT_ERROR", "Too many streams opened"},
    0x05 => {"STREAM_STATE_ERROR", "Frame received in invalid stream state"},
    0x06 => {"FINAL_SIZE_ERROR", "Change to final size"},
    0x07 => {"FRAME_ENCODING_ERROR", "Frame encoding error"},
    0x08 => {"TRANSPORT_PARAMETER_ERROR", "Error in transport parameters"},
    0x09 => {"CONNECTION_ID_LIMIT_ERROR", "Too many connection IDs received"},
    0x0A => {"PROTOCOL_VIOLATION", "Generic protocol violation"},
    0x0B => {"INVALID_TOKEN", "Invalid Token received"},
    0x0C => {"APPLICATION_ERROR", "Application error"},
    0x0D => {"CRYPTO_BUFFER_EXCEEDED", "CRYPTO data buffer overflowed"},
    0x0E => {"KEY_UPDATE_ERROR", "Invalid packet protection update"},
    0x0F => {"AEAD_LIMIT_REACHED", "Excessive use of packet protection keys"},
    0x10 => {"NO_VIABLE_PATH", "No viable network path exists"}
  }

  tls_errors = for i <- 0x0100..0x01FF, into: %{}, do: {i, {"CRYPTO_ERROR", "TLS alert code"}}

  @table Map.merge(quic_errors, tls_errors)

  def mapping, do: @table

  for {i, {code, msg}} <- quic_errors do
    def unquote(code |> String.downcase() |> String.to_atom())() do
      exception(value: unquote(i), code: unquote(code), message: unquote(msg))
    end
  end

  def exception(value) when is_integer(value) do
    case Map.fetch(mapping(), value) do
      {:ok, {code, msg}} -> super(value: value, code: code, message: msg)
      :error -> raise "invalid error value"
    end
  end

  def exception(term) do
    super(term)
  end
end
