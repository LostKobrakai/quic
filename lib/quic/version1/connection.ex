defmodule Quic.Version1.Connection do
  use GenStateMachine
  require Logger

  defstruct [:transport_parameters]

  # handshake phase -> normal

  def generate_connection_id, do: :crypto.strong_rand_bytes(16)

  def start_link({%Quic.Config{} = config, _, connection_id} = init_arg) do
    GenStateMachine.start_link(__MODULE__, init_arg, name: via(config, connection_id))
  end

  def process_packet(%Quic.Config{} = config, connection_id, packet) do
    GenStateMachine.cast(via(config, connection_id), {:process_packet, packet})
  end

  @impl GenStateMachine
  def init({%Quic.Config{} = config, addressing_information, original_connection_id}) do
    Logger.info("Starting connection for #{Base.encode16(original_connection_id)}")
    connection_id = generate_connection_id()

    Quic.Registry.register(config, {__MODULE__, connection_id})

    {:ok, :handshake,
     %{
       addressing_information: addressing_information,
       config: config,
       original_connection_id: original_connection_id,
       connection_id: connection_id
     }}
  end

  @impl GenStateMachine
  def handle_event(:cast, {:process_packet, packet}, _, data)
      when packet.destination_connection_id in [data.original_connection_id, data.connection_id] do
    {:ok, protocol_packet, _rest} = Quic.Version1.parse_contextless(packet)
    [[<<0x06>>, client_hello] | _] = protocol_packet.frames

    # Not sure why the first 4 bytes need to be stripped
    Quic.Version1.TLS.parse_client_hello(binary_slice(client_hello, 4..-1//1))
    |> IO.inspect()

    :keep_state_and_data
  end

  def handle_event(:cast, {:process_packet, packet}, _state, data)
      when packet.destination_connection_id not in [
             data.original_connection_id,
             data.connection_id
           ] do
    Logger.info("Discarding packet for non-matching connection ID: #{inspect(packet)}")
    :keep_state_and_data
  end

  defp via(%Quic.Config{} = config, connection_id) do
    Quic.Registry.via(config, {__MODULE__, connection_id})
  end
end
