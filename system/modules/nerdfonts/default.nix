{
  pkgs,
  config,
  ...
}: let
  # hank wanted RecMonoSmCasual's italic to be Cascadia Code's cursive rather
  # than Recursive's oblique; nobody else asked for it, and this machine list is
  # shared with linwhite's and kenneth's boxes.
  #
  # It has to be a swap rather than an addition: the replacement keeps the
  # family name, so installing it next to nerd-fonts.recursive-mono would leave
  # fontconfig with two different files claiming to be "RecMonoSmCasual Nerd
  # Font Mono Italic". Everything else in the set is passed through unchanged,
  # so RecMonoLinear and friends are unaffected either way.
  #
  # Keying off the account list rather than the hostname means a new machine of
  # his picks this up on its own.
  recursiveMono =
    if builtins.elem "hank" config.my.host.usernames
    then pkgs.callPackage ../../../pkgs/recursive-mono-cascadia-italic {}
    else pkgs.nerd-fonts.recursive-mono;
in {
  fonts.packages = with pkgs; [
    noto-fonts
    noto-fonts-cjk-sans
    noto-fonts-color-emoji
    liberation_ttf
    nerd-fonts.fira-code
    nerd-fonts.droid-sans-mono
    recursiveMono
    mplus-outline-fonts.githubRelease
    dina-font
    proggyfonts
  ];
}
