defmodule Quic.MixProject do
  use Mix.Project

  def project do
    [
      app: :quic,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :ssl]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:bandit, "~> 1.0", only: :dev}
    ]
  end

  def aliases do
    [
      setup: [&create_certs/1],
      dev: ["run --no-halt dev.exs"]
    ]
  end

  def create_certs(_) do
    key_path = Path.join(Mix.Project.build_path(), "key.pem")
    cert_path = Path.join(Mix.Project.build_path(), "cert.pem")
    Mix.shell().cmd("mkcert -key-file #{key_path} -cert-file #{cert_path} localhost")
  end
end
