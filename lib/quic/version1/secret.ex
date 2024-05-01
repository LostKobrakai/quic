defmodule Quic.Version1.Secret do
  @hex_initial_salt "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

  def initial_salt, do: unquote(Base.decode16!(@hex_initial_salt, case: :lower))

  def initial_secret(client_destination_connection_id) do
    :tls_v1.hkdf_extract(
      :sha256,
      initial_salt(),
      client_destination_connection_id
    )
  end

  def client_initial_secret(initial_secret) do
    hkdf_expand_label(initial_secret, "client in", 32)
  end

  def server_initial_secret(initial_secret) do
    hkdf_expand_label(initial_secret, "server in", 32)
  end

  def key(secret) do
    hkdf_expand_label(secret, "quic key", 16)
  end

  def iv(secret) do
    hkdf_expand_label(secret, "quic iv", 12)
  end

  def header_protection_key(secret) do
    hkdf_expand_label(secret, "quic hp", 16)
  end

  def mask(key, sample) do
    <<mask::binary-size(5), _::binary-size(11)>> =
      :crypto.crypto_one_time(:aes_128_ecb, key, sample, true)

    mask
  end

  @compile {:inline, hkdf_expand_label: 3}
  # Context is always empty
  defp hkdf_expand_label(secret, key, length) do
    :tls_v1.hkdf_expand_label(secret, key, "", length, :sha256)
  end
end
