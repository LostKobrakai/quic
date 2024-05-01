defmodule Quic.Development do
  def processes do
    port = port()

    children = [
      {Quic, port: port},
      {Bandit,
       plug: fn conn, _ ->
         conn
         |> Plug.Conn.put_resp_header("alt-svc", ~s|h3=":#{port}"; ma=900|)
         |> Plug.Conn.send_resp(200, "")
       end,
       scheme: :https,
       port: port,
       certfile: cert_location("cert.pem"),
       keyfile: cert_location("key.pem")},
      {Task, fn -> Mix.shell().info("Access the endpoint at https://localhost:#{port}") end}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end

  defp cert_location(file), do: Path.join(Mix.Project.build_path(), file)
  defp port, do: 4003
end

Task.start(fn ->
  {:ok, _} = Quic.Development.processes()
  Process.sleep(:infinity)
end)
