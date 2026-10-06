{
  fetchurl,
  lib,
  python3Packages,
}: python3Packages.buildPythonPackage {
  pname = "pyobjc-framework-NetFS";
  version = "11.1";
  format = "wheel";
  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/77/cc/199b06f214f8a2db26eb47e3ab7015a306597a1bca25dcb4d14ddc65bd4a/pyobjc_framework_netfs-11.1-py2.py3-none-any.whl";
    sha256 = "f202e8e0c2e73516d3eac7a43b1c66f9911cdbb37ea32750ed197d82162c994a";
  };
  dependencies = with python3Packages; [
    pyobjc-core
    pyobjc-framework-Cocoa
  ];
  pythonImportsCheck = ["NetFS"];
  meta = {
    description = "PyObjC bindings for the macOS NetFS framework";
    license = lib.licenses.mit;
    platforms = lib.platforms.darwin;
  };
}
