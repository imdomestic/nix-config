{
  lib,
  llama-cpp,
  cudaPackages_12_9,
  fetchFromGitHub,
  nodejs,
  npmHooks,
}: let
  revision = "adfffbe41b2cabcd51fff326ab045662265062bb";
in
  (llama-cpp.override {
    cudaSupport = true;
    cudaPackages = cudaPackages_12_9;
  }).overrideAttrs (old: {
    pname = "llama-cpp-prism";
    version = "prism-b10743-adfffbe";
    src = fetchFromGitHub {
      owner = "PrismML-Eng";
      repo = "llama.cpp";
      rev = revision;
      hash = "sha256-SNBAC+dNTwQxpGmKyG7i/8eqCNg6985DXtqGbzWgwFA=";
    };
    # 本服务通过 OpenAI API 接入 opencode，关闭独立网页界面的构建。
    nativeBuildInputs =
      builtins.filter
      (input: !(lib.elem input [nodejs npmHooks.npmConfigHook]))
      old.nativeBuildInputs;
    npmDeps = null;
    preConfigure = "";
    cmakeFlags =
      builtins.filter
      (flag:
        !(lib.hasPrefix "-DCMAKE_CUDA_ARCHITECTURES" flag)
        && !(lib.hasPrefix "-DLLAMA_BUILD_NUMBER" flag))
      old.cmakeFlags
      ++ [
        (lib.cmakeFeature "CMAKE_CUDA_ARCHITECTURES" "120")
        (lib.cmakeFeature "LLAMA_BUILD_NUMBER" "10743")
        (lib.cmakeFeature "LLAMA_BUILD_COMMIT" revision)
        (lib.cmakeBool "LLAMA_BUILD_UI" false)
        (lib.cmakeBool "LLAMA_USE_PREBUILT_UI" false)
        (lib.cmakeBool "LLAMA_BUILD_APP" false)
      ];
    meta =
      old.meta
      // {
        description = "PrismML llama.cpp with PQ2_0 and MTP for RTX 5070";
        homepage = "https://github.com/PrismML-Eng/llama.cpp";
        mainProgram = "llama-server";
      };
  })
