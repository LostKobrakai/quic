defmodule Quic.Version1.Encoding do
  def encode_variable_length_integer(int) when int in 0..63 do
    <<0::2, int::6>>
  end

  def encode_variable_length_integer(int) when int in 64..16383 do
    <<1::2, int::14>>
  end

  def encode_variable_length_integer(int) when int in 16384..1_073_741_823 do
    <<2::2, int::30>>
  end

  def encode_variable_length_integer(int) when int in 1_073_741_824..4_611_686_018_427_387_903 do
    <<3::2, int::62>>
  end

  def decode_variable_length_integer(<<0::2, integer::6, rest::bitstring>>) do
    {integer, rest}
  end

  def decode_variable_length_integer(<<1::2, integer::14, rest::bitstring>>) do
    {integer, rest}
  end

  def decode_variable_length_integer(<<2::2, integer::30, rest::bitstring>>) do
    {integer, rest}
  end

  def decode_variable_length_integer(<<3::2, integer::62, rest::bitstring>>) do
    {integer, rest}
  end
end
