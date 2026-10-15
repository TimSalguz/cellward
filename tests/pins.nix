# Pinned sources shared by the test harness (harness.nix) and the VM test
# (vm.nix). flake.nix deliberately has no inputs, so the pins live here: a
# specific commit of a stable branch with an explicit sha256 — reproducible
# and immune to the branch moving.
#
# Updating:
#   git ls-remote https://github.com/NixOS/nixpkgs refs/heads/nixos-XX.YY
#   nix-prefetch-url --unpack https://github.com/NixOS/nixpkgs/archive/<rev>.tar.gz
#   (same for home-manager, branch release-XX.YY; then bump home.stateVersion
#   in harness.nix and vm.nix to match the branch)
{
  # nixpkgs, branch nixos-26.05
  nixpkgs = builtins.fetchTarball {
    name = "nixpkgs-nixos-26.05-a033e66a";
    url = "https://github.com/NixOS/nixpkgs/archive/a033e66ab94a6bedf2c3d58d93a36319d3cbbbaf.tar.gz";
    sha256 = "140gms89455qvs29g7zwnx66z0h9ycf4hvfg7lh84rqi79sh7yfa";
  };

  # home-manager, branch release-26.05 (paired with the nixpkgs above)
  home-manager = builtins.fetchTarball {
    name = "home-manager-release-26.05-65258d5c";
    url = "https://github.com/nix-community/home-manager/archive/65258d5c65a250189fde2e35f490d15e064c4c62.tar.gz";
    sha256 = "1qsx6l8z2v2rzr47chfqvmr9585lcrb2wihixbklmz63nhsba6sb";
  };
}
