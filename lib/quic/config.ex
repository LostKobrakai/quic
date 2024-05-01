defmodule Quic.Config do
  defstruct [:port]

  @type t :: %__MODULE__{
          port: pos_integer()
        }

  def new(arg) do
    port = Keyword.fetch!(arg, :port)

    %__MODULE__{
      port: port
    }
  end
end
