defmodule Quic.ProtocolVersion do
  alias Quic.VersionIndependent

  @type t :: module()

  @callback child_spec(term) :: Supervisor.child_spec()

  @callback transfer_handling(Quic.Config.t(), VersionIndependent.packet()) :: :ok
end
