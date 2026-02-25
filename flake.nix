{
  description = "GyoiThon: Next generation penetration test tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        pythonEnv = pkgs.python3.withPackages (ps: with ps; [
          beautifulsoup4
          chardet
          censys
          docopt
          google-api-python-client
          jinja2
          matplotlib
          msgpack
          networkx
          pandas
          pysocks
          scrapy
          tldextract
          urllib3
          streamlit
          selenium
          # Dependencies that might be needed implicitly
          lxml
          pillow
          requests
          tornado
          watchdog
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pythonEnv
            pkgs.bashInteractive
          ];

          shellHook = ''
            echo "Welcome to GyoiThon dev environment!"
            echo "Python $(python --version) is ready."
            echo "Run 'streamlit run dashboard.py' to start the dashboard."
          '';
        };
      }
    );
}
