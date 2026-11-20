# docs

- `incidents.md`: what went wrong and what misled us, newest first.
- `decisions.md`: why something is the way it is, or is not there at all, newest first.
- `hosts/`: one machine each: hardware, disks, boot, what runs there.
- `services/`: how a fleet service works and how to operate it.
- `home/`: what one account's home sets up.
- `runbooks/`: step-by-step procedures for rescue and recovery.

| Where | Doc |
| --- | --- |
| hosts | [encore](hosts/encore.md), [seraph](hosts/seraph.md), [tokyo](hosts/tokyo.md), [268v Windows VM and iGPU passthrough](268v-windows-vfio.md) |
| services | [agy-proxy](agy-proxy.md), [Bonsai](services/bonsai.md), [Clef](services/clef.md), [CLIProxyAPI](services/cliproxy.md), [GPU monitoring](services/gpu-monitoring.md), [linwhite's SMB shares](services/linwhite-smb.md), [Lumiverse](services/lumiverse.md), [Max SSH operations](services/max-ssh-operations.md), [Minecraft network](minecraft-network-todo.md), [proxy chain](services/proxy.md), [Rewind](rewind.md), [SillyTavern](services/sillytavern.md), [Tailscale names](services/tailscale-names.md) |
| home | [Claude Code mods](home/claude-code-mods.md), [Ghostty cursor](ghostty-cursor.md), [Pi model pricing](home/pi-model-pricing.md), [Pi subagents](home/pi-subagents.md), [Rex](home/rex.md), [Safari MRU](safari-mru.md), [VS Code / Neovim](home/vscode-neovim.md) |
| runbooks | [macOS VM](runbooks/macos-vm.md), [QQ fixed primary](runbooks/qq-fixed-primary.md), [r6s](runbooks/r6s.md), [seraph Secure Boot](runbooks/seraph-secure-boot.md), [USB rescue](runbooks/usb-rescue.md) |

Six docs stay at the top level although they belong in a folder: a source file
that is copied into the Nix store names each one (`pkgs/agy-proxy/proxy.go`,
`pkgs/cliproxy-rewind/model_relay.go`, the Ghostty shaders, `pkgs/safari-mru/main.m`,
the `minecraft/` sources, `scripts/vfio-probe/linux-guest.sh`). Moving one means
editing that comment, which rebuilds the package, and for `minecraft/` changes
the image tag and rolls out the servers.
