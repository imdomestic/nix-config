{
  lib,
  edk2,
  fetchFromGitHub,
  nasm,
  python3,
  ...
}: let
  source = fetchFromGitHub {
    owner = "tomitamoeko";
    repo = "VfioIgdPkg";
    rev = "067328df2554c865cc0078cb922357301c4c36c6";
    hash = "sha256-/Eifaa6NFpxFvM4ELbeJqwXWLYQEAHKG7SrxiWom23M=";
  };
in
  edk2.mkDerivation "VfioIgdPkg/VfioIgdPkg.dsc" {
    pname = "vfio-igd-rom";
    version = "0-unstable-067328d";
    nativeBuildInputs = [nasm python3];
    postPatch = ''
      cp -r ${source} VfioIgdPkg
      chmod -R u+w VfioIgdPkg
    '';
    env.PYTHON_COMMAND = "${python3}/bin/python3";
    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      EfiRom -f 0x8086 -i 0x64a0 \
        -e Build/VfioIgdPkg/RELEASE_GCC5/X64/IgdAssignmentDxe.efi \
        -o "$out/igd-64a0.rom"
      install -Dm644 ${source}/LICENSE "$out/share/licenses/vfio-igd-rom/LICENSE"
      runHook postInstall
    '';
    dontStrip = true;
    dontPatchELF = true;
    meta = {
      description = "Intel 64a0 VFIO OpRegion initialization ROM without proprietary GOP";
      homepage = "https://github.com/tomitamoeko/VfioIgdPkg";
      license = lib.licenses.bsd2;
      platforms = ["x86_64-linux"];
    };
  }
