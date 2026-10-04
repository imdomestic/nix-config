{
  symlinkJoin,
  go,
  git,
  curl,
  coreutils,
  fetchurl,
  fetchFromGitHub,
  autoPatchelfHook,
  stdenv,
  zlib,
}: let
  pythonPkgs = import (fetchFromGitHub {
    owner = "NixOS";
    repo = "nixpkgs";
    rev = "b6018f87da91d19d0ab4cf979885689b469cdd41";
    hash = "sha256-twXPFqFsrrY5r28Zh7Homgcp2gUMBgQ6WDS98Q/3xFI=";
  }) {inherit (stdenv.hostPlatform) system;};
  ps = pythonPkgs.python311.pkgs;
  torchCpu = ps.buildPythonPackage {
    pname = "torch";
    version = "2.11.0+cpu";
    format = "wheel";
    src = fetchurl {
      url = "https://download-r2.pytorch.org/whl/cpu/torch-2.11.0%2Bcpu-cp311-cp311-manylinux_2_28_x86_64.whl";
      hash = "sha256-ilaoyVUx7w5FRRC6i72dEdx6kAAzcmUhCxD2v+rN1IU=";
    };
    nativeBuildInputs = [autoPatchelfHook];
    buildInputs = [stdenv.cc.cc.lib zlib];
    dependencies = with ps; [filelock typing-extensions setuptools sympy networkx jinja2 fsspec];
    pythonImportsCheck = ["torch"];
  };
  python = pythonPkgs.python311.withPackages (_: [ps.numpy torchCpu]);
in
  symlinkJoin {
    name = "bonsai-convert-env";
    paths = [python go git curl coreutils];
  }
