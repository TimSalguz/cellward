# Политика WirePlumber для PipeWire зон (docs/LEAK-MODEL.md §17) — модулем
# NixOS, через services.pipewire.wireplumber.extraConfig/extraScripts.
# Подключается из module/nixos.nix; от системных зон не зависит: нужна
# пользовательскому уровню. Для home-manager без NixOS то же самое —
# programs.vpn-zones.pipewirePolicy (те же имена файлов, включённые оба не
# дублируются).
{ config, lib, ... }:
{
  options.services.vpn-zones.pipewirePolicy.enable = lib.mkEnableOption ''
    the WirePlumber policy of vpn-zones for the zones' PipeWire clients: a
    hermetic zone's programs see only their own streams, the outputs to play
    to and — as its microphone setting says — the capture sources, never a
    monitor, and make no links. Without it a hermetic zone gets no PipeWire
    socket at all (sound through the pulse filter only). WirePlumber picks it
    up when it restarts'';

  config = lib.mkIf config.services.vpn-zones.pipewirePolicy.enable {
    services.pipewire.wireplumber.extraConfig."90-vpn-zones" = import ./config.nix;
    services.pipewire.wireplumber.extraScripts."vpn-zones/policy.lua" =
      builtins.readFile ./policy.lua;
  };
}
