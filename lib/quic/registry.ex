defmodule Quic.Registry do
  def child_spec(_) do
    Registry.child_spec(name: __MODULE__, keys: :unique)
  end

  def register(%Quic.Config{port: port}, process) do
    Registry.register(__MODULE__, {port, process}, nil)
  end

  def via(%Quic.Config{port: port}, process) do
    {:via, Registry, {__MODULE__, {port, process}}}
  end
end
