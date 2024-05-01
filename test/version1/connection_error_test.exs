defmodule Quic.Version1.ConnectionErrorTest do
  use ExUnit.Case, async: true
  alias Quic.Version1.ConnectionError

  describe "error functions" do
    test "internal error" do
      assert %ConnectionError{
               value: 0x01,
               code: "INTERNAL_ERROR",
               message: "Implementation error"
             } = ConnectionError.internal_error()
    end

    @compile {:no_warn_undefined, {ConnectionError, :crypto_error, 0}}
    test "doesn't work for tls error, which has no unique code per value" do
      assert_raise(
        UndefinedFunctionError,
        "function Quic.Version1.ConnectionError.crypto_error/0 is undefined or private",
        fn -> ConnectionError.crypto_error() end
      )
    end
  end

  describe "create from error value" do
    test "internal error" do
      assert %ConnectionError{
               value: 0x01,
               code: "INTERNAL_ERROR",
               message: "Implementation error"
             } = ConnectionError.exception(0x01)
    end

    test "doesn't work for invalid error values" do
      assert_raise(
        RuntimeError,
        "invalid error value",
        fn -> ConnectionError.exception(0x0200) end
      )
    end
  end
end
