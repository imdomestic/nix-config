# Home tiers: how much of an environment an account gets on a host. Each tier
# includes the ones below it.
#
#   minimal      ./home-base.nix only — the standalone HM plumbing
#   shell        + the account's shell.nix (home/users/<account>/)
#   interactive  + its interactive.nix
#   dev          + its dev.nix
{lib}: let
  names = ["minimal" "shell" "interactive" "dev"];
  rank = t: lib.lists.findFirstIndex (n: n == t) null names;
in {
  inherit names;
  type = lib.types.enum names;
  atLeast = tier: floor: rank tier >= rank floor;
  min = a: b:
    if rank a <= rank b
    then a
    else b;
}
