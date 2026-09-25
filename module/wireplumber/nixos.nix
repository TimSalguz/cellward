# Политика WirePlumber для PipeWire зон (docs/LEAK-MODEL.md §20) — модулем
# NixOS. Подключается из module/nixos.nix; от системных зон не зависит: нужна
# пользовательскому уровню. Для home-manager без NixOS то же самое —
# programs.vpn-zones.pipewirePolicy (те же имена файлов, включённые оба не
# дублируются).
#
# Скрипт — через services.pipewire.wireplumber.extraScripts. Фрагмент
# конфигурации — пакетом (configPackages), а не через extraConfig: тот пишет
# разделы builtins.toJSON, то есть с кавычками вокруг каждой строки, а
# WirePlumber 0.5.14 берёт имя возможности в `wants` вместе с кавычками — и
# не поднимается вовсе (сеанс без звука; найдено VM-тестом vm-audio).
{
  config,
  lib,
  pkgs,
  ...
}:
{
  options.services.vpn-zones.pipewirePolicy.enable = lib.mkEnableOption ''
    the WirePlumber policy of vpn-zones for the zones' PipeWire clients: a
    hermetic zone's programs see only their own streams, the outputs to play
    to and — as its microphone setting says — the capture sources, never a
    monitor, and make no links. Without it a hermetic zone gets no PipeWire
    socket at all (sound through the pulse filter only). WirePlumber picks it
    up when it restarts. WirePlumber looks for scripts and fragments in the
    home first (~/.local/share/wireplumber, ~/.config/wireplumber): a
    hermetic zone has those, ~/.config/pipewire and ~/.local/state/wireplumber
    read-only, made beforehand when missing — a zone that may write the
    host's files (hostFilesWritable) can replace the policy for every zone'';

  config = lib.mkIf config.services.vpn-zones.pipewirePolicy.enable {
    services.pipewire.wireplumber.configPackages = [
      (pkgs.writeTextDir "share/wireplumber/wireplumber.conf.d/90-vpn-zones.conf" (
        builtins.readFile ./90-vpn-zones.conf
      ))
    ];
    services.pipewire.wireplumber.extraScripts."vpn-zones/policy.lua" =
      builtins.readFile ./policy.lua;
  };
}
