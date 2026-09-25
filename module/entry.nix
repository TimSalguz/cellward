# ЕДИНЫЙ ВХОД cellward: programs.cellward.enable (README, «Установка»).
#
# Один импорт (nixosModules.default) и одна строка — и на машине есть то, что
# cellward нужно в любом случае. Осознанный выбор остаётся явным: системный
# уровень (system.enable), политика хоста (system.egress, её режим и аварийный
# ключ), host.dns, пульт TTY и выключатель — их этот модуль не включает.
#
# Что включается:
#   • модули ядра, которые зона сама не загрузит — ядро не грузит модули по
#     запросу из непривилегированного user namespace: amneziawg (если не
#     system.amneziawg = false), ядерный wireguard (запасной путь для
#     конфигов без обфускации), tun (pasta) и nf_tables (второй эшелон,
#     docs/LEAK-MODEL.md);
#   • политика WirePlumber для PipeWire зон — по умолчанию там, где
#     WirePlumber и так работает;
#   • модуль home-manager — каждому пользователю home-manager, если подключён
#     его модуль NixOS, с programs.cellward.enable по умолчанию;
#   • при включённой политике хоста — выход демону Nix и часам через простую
#     зону direct0, если host.nix и host.time не заданы (пример README).
{
  config,
  options,
  lib,
  ...
}:

let
  top = config.services.cellward;
  # The entry is `programs.cellward.enable`, as in home-manager: in NixOS,
  # `programs.*` is where a tool that also sets up the system lives
  # (programs.firejail, programs.wireshark); `services.*` is for daemons —
  # the system tier and the PipeWire policy stay there.
  on = config.programs.cellward.enable;
  cfg = top.system;
  # The plain zone the Nix daemon and the clock go out through when the
  # egress policy is on and they have no zone of their own.
  directZone = "direct0";
in
{
  # The name the entry had first (2026-09-25): still read, with a warning.
  imports = [
    (lib.mkRenamedOptionModule
      [ "services" "cellward" "enable" ]
      [ "programs" "cellward" "enable" ]
    )
  ];

  options.programs.cellward.enable = lib.mkEnableOption ''
    cellward on this machine in one line: the kernel modules a zone cannot
    load from its unprivileged user namespace (`amneziawg` unless
    `system.amneziawg = false`, `wireguard`, `tun`, `nf_tables`); the
    PipeWire policy (`pipewirePolicy.enable`) by default when WirePlumber
    runs; with the home-manager NixOS module, the home-manager module for
    every home-manager user, `programs.cellward.enable` true by default; and,
    with the system tier's egress policy on, a plain zone `direct0` the Nix
    daemon and systemd-timesyncd go out through unless `system.host.nix` and
    `system.host.time` say otherwise. It turns on neither the system tier nor
    the egress policy'';

  config = lib.mkMerge [
    (lib.mkIf on {
      # amneziawg is loaded by the system tier itself when that is on
      # (module/nixos.nix): one entry in the list, not two.
      boot.extraModulePackages = lib.mkIf (cfg.amneziawg && !cfg.enable) [
        config.boot.kernelPackages.amneziawg
      ];
      boot.kernelModules = lib.optional (cfg.amneziawg && !cfg.enable) "amneziawg" ++ [
        "wireguard"
        "tun"
        "nf_tables"
      ];

      services.cellward.pipewirePolicy.enable = lib.mkIf config.services.pipewire.wireplumber.enable (
        lib.mkDefault true
      );

      # Defaults, not definitions: an explicit host.nix or host.time — null
      # for the host's own network — wins, and so does a zone of the user's
      # own named direct0. host.time only for timesyncd: another time daemon
      # goes into a zone with services.<unit>.
      services.cellward.system = lib.mkIf (cfg.enable && cfg.egress.enable) {
        host.nix = lib.mkDefault directZone;
        host.time = lib.mkIf config.services.timesyncd.enable (lib.mkDefault directZone);
        zones = lib.mkIf (cfg.host.nix == directZone || cfg.host.time == directZone) {
          ${directZone} = lib.mkDefault { kind = "plain"; };
        };
      };
    })

    # The home-manager module for every home-manager user, on by default.
    # `./.` is the path the flake's homeModules.default names: importing it
    # by hand as well is the same module, taken once.
    (lib.optionalAttrs (options ? home-manager) {
      home-manager.sharedModules = lib.mkIf on [
        ./.
        { programs.cellward.enable = lib.mkDefault true; }
      ];
    })
  ];
}
