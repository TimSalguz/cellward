# СИСТЕМНЫЙ УРОВЕНЬ vpn-zones (ROADMAP M10, docs/SYSTEM.md, docs/ARCHITECTURE.ru.md).
#
# Та же зона, что у пользовательского уровня, — namespace, где есть только lo и
# туннель, — но держит её systemd с загрузки, а не сеанс. К ней подключаются
# системные службы и NixOS-контейнеры, которым нужна сеть «только через VPN»
# даже тогда, когда в систему никто не вошёл (торрент-клиент, Syncthing).
#
# Модуль необязательный и от домашнего не зависит: без него всё остаётся
# rootless, как было. Ключи зон в Nix не объявляются: конфиг лежит локально в
# /var/lib/vpn-zones/system/<имя>/config.conf (0600, root), либо `configFile`
# указывает на расшифрованный секрет (sops-nix, agenix).
#
# Что создаётся на каждую зону:
#   vpn-zone-system-ns-<имя>  namespace /run/netns/vz-<имя>: lo, второй эшелон,
#                             пустой resolv.conf. НЕ перезапускается при switch —
#                             иначе каждое обновление пакета выдёргивало бы
#                             namespace из-под всех, кто в нём живёт;
#   vpn-zone-system-<имя>     туннель: создаётся в сети хоста (там и остаётся
#                             его UDP-сокет), переезжает в зону как awg0; потом
#                             зеркало состояния в /run/vpn-zones/system/<имя>/.
#
# Службы и контейнеры привязаны к namespace (bindsTo), а за туннелем только
# идут следом (wants/after): упал туннель — у них остаётся один lo и ни одного
# пути наружу; пропал namespace — они останавливаются, потому что процесс в
# удалённом namespace отрезан насовсем.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.vpn-zones.system;

  vpn-zone-rust = pkgs.callPackage ../package.nix { };
  core = "${vpn-zone-rust}/bin/vpn-zone-core";
  # Абсолютные пути, как у пользовательского держателя: часть команд идёт
  # через `ip netns exec`, и PATH там ни при чём.
  tools = lib.concatStringsSep " " [
    "--ip ${pkgs.iproute2}/bin/ip"
    "--awg ${pkgs.amneziawg-tools}/bin/awg"
    "--wg ${pkgs.wireguard-tools}/bin/wg"
    "--nft ${pkgs.nftables}/bin/nft"
  ];

  nsUnit = zone: "vpn-zone-system-ns-${zone}";
  holderUnit = zone: "vpn-zone-system-${zone}";
  netnsPath = zone: "/run/netns/vz-${zone}";
  resolvPath = zone: "/etc/netns/vz-${zone}/resolv.conf";

  # То же правило, что system::check_name в крейте: vz-<имя> — это ещё и имя
  # интерфейса в сети хоста, а их длина кончается на 15.
  validName =
    name:
    builtins.match "[a-z0-9][a-z0-9-]{0,11}" name != null
    && !(builtins.elem name [
      "unconfined"
      "direct"
      "offline"
    ]);

  consumerDeps = zone: {
    bindsTo = [ "${nsUnit zone}.service" ];
    after = [
      "${nsUnit zone}.service"
      "${holderUnit zone}.service"
    ];
    wants = [ "${holderUnit zone}.service" ];
  };

  zoneOpts = {
    options = {
      configFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/run/secrets/vpn-nl";
        description = ''
          Where the zone's WireGuard/AmneziaWG config is at run time, when it is
          not `/var/lib/vpn-zones/system/<name>/config.conf`. A string and not a
          path on purpose: a path would be copied into the world-readable Nix
          store together with the private key. Point it at a decrypted secret
          and list the holder in that secret's `restartUnits`.
        '';
      };
      autoStart = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Bring the zone up at boot. Otherwise it comes up when something bound to it starts, or with `systemctl start vpn-zone-system-<name>`.";
      };
    };
  };

  serviceOpts = {
    options = {
      zone = lib.mkOption {
        type = lib.types.str;
        description = "The system zone the service runs in.";
      };
      systemBus = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Leave the host's system bus reachable. Off by default: systemd-resolved
          answers name lookups over it (`org.freedesktop.resolve1`), in the
          host's network, around the tunnel.
        '';
      };
    };
  };

  containerOpts = {
    options.zone = lib.mkOption {
      type = lib.types.str;
      description = "The system zone the NixOS container runs in.";
    };
  };
in
{
  options.services.vpn-zones.system = {
    enable = lib.mkEnableOption "system zones of vpn-zones: network namespaces with a tunnel as their only way out, held from boot, for services and NixOS containers";

    zones = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule zoneOpts);
      default = { };
      example = lib.literalExpression ''{ nl = { }; work.configFile = "/run/secrets/vpn-work"; }'';
      description = "The system zones. A name is 1 to 12 of a-z, 0-9 and '-'.";
    };

    services = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule serviceOpts);
      default = { };
      example = lib.literalExpression ''{ qbittorrent.zone = "nl"; }'';
      description = ''
        System services to run in a zone, by their `systemd.services` name. The
        service gets the zone's network namespace and resolv.conf; nscd,
        resolved's varlink socket and (unless `systemBus`) the system bus are
        hidden from it, because each of them resolves names through the host.
      '';
    };

    containers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule containerOpts);
      default = { };
      example = lib.literalExpression ''{ torrent.zone = "nl"; }'';
      description = ''
        NixOS containers (`containers.<name>`) to run in a zone. The container
        gets the zone's network namespace and resolv.conf, its own user
        namespace (`privateUsers = "pick"`, so its root can't touch the zone's
        routes) and no access to the host's Nix daemon, which would otherwise
        download anything it is asked to in the host's network.
      '';
    };

    amneziawg = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Load the out-of-tree amneziawg kernel module (built for the running
        kernel). Without it only configs with no obfuscation parameters work,
        through the in-tree wireguard module.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions =
          lib.mapAttrsToList (name: _: {
            assertion = validName name;
            message = "services.vpn-zones.system.zones.${name}: a system zone is named by 1 to 12 of a-z, 0-9 and '-', not starting with '-', and not unconfined, direct or offline.";
          }) cfg.zones
          ++ lib.mapAttrsToList (unit: s: {
            assertion = cfg.zones ? ${s.zone};
            message = "services.vpn-zones.system.services.${unit}.zone = \"${s.zone}\": there is no such zone in services.vpn-zones.system.zones.";
          }) cfg.services
          ++ lib.concatLists (
            lib.mapAttrsToList (
              c: a:
              let
                ct = config.containers.${c};
              in
              [
                {
                  assertion = cfg.zones ? ${a.zone};
                  message = "services.vpn-zones.system.containers.${c}.zone = \"${a.zone}\": there is no such zone in services.vpn-zones.system.zones.";
                }
                {
                  # Без своего user namespace root контейнера — root и в
                  # namespace зоны: мог бы добавить маршрут или интерфейс мимо
                  # туннеля.
                  assertion =
                    !(builtins.elem ct.privateUsers [
                      "no"
                      "identity"
                      0
                    ]);
                  message = "containers.${c} runs in the system zone ${a.zone}: its privateUsers must give it a user namespace of its own (\"pick\" or a range), or its root could route around the tunnel.";
                }
                {
                  assertion = !ct.enableTun && !(builtins.elem "CAP_NET_ADMIN" ct.additionalCapabilities);
                  message = "containers.${c} runs in the system zone ${a.zone}: no enableTun and no CAP_NET_ADMIN — a network of its own is exactly what the zone takes away.";
                }
                {
                  # Сеть контейнера — сеть зоны, в которой запущен nspawn:
                  # любой из этих флагов дал бы ему другую.
                  assertion =
                    !ct.privateNetwork
                    && ct.networkNamespace == null
                    && ct.interfaces == [ ]
                    && ct.macvlans == [ ]
                    && ct.extraVeths == { };
                  message = "containers.${c} runs in the system zone ${a.zone}: its network is the zone's, so privateNetwork, networkNamespace, interfaces, macvlans and extraVeths have to stay unset.";
                }
              ]
            ) cfg.containers
          );

        users.groups.vpn-zones = { };

        # Список для `vpn-zone status --json` (system_networks).
        environment.etc."vpn-zones/system-zones".text = lib.concatMapStrings (name: name + "\n") (
          lib.attrNames cfg.zones
        );

        boot.extraModulePackages = lib.mkIf cfg.amneziawg [ config.boot.kernelPackages.amneziawg ];
        boot.kernelModules = lib.mkIf cfg.amneziawg [ "amneziawg" ];

        # Каталог запуска зоны — 2750 root:vpn-zones: группа читает состояние,
        # а новые файлы наследуют группу от setgid-каталога.
        systemd.tmpfiles.rules = [
          "d /run/vpn-zones 0755 root root -"
          "d /run/vpn-zones/system 0755 root root -"
          "d /var/lib/vpn-zones 0755 root root -"
          "d /var/lib/vpn-zones/system 0700 root root -"
        ]
        ++ lib.concatLists (
          lib.mapAttrsToList (name: _: [
            "d /run/vpn-zones/system/${name} 2750 root vpn-zones -"
            "d /var/lib/vpn-zones/system/${name} 0700 root root -"
          ]) cfg.zones
        );

        systemd.services = lib.mkMerge (
          lib.mapAttrsToList (name: z: {
            ${nsUnit name} = {
              description = "vpn-zones: network namespace of the system zone ${name}";
              wantedBy = lib.mkIf z.autoStart [ "multi-user.target" ];
              restartIfChanged = false;
              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                ExecStart = "${core} system-zone ns-up ${tools} ${name}";
                ExecStop = "${core} system-zone ns-down ${tools} ${name}";
              };
            };
            ${holderUnit name} = {
              description = "vpn-zones: the tunnel of the system zone ${name}";
              bindsTo = [ "${nsUnit name}.service" ];
              after = [
                "${nsUnit name}.service"
                "network-online.target"
              ];
              wants = [ "network-online.target" ];
              wantedBy = lib.mkIf z.autoStart [ "multi-user.target" ];
              serviceConfig = {
                # READY=1 — после настройки туннеля и resolv.conf зоны: всё,
                # что идёт следом, стартует уже с сетью, а не с одним lo.
                Type = "notify";
                ExecStart =
                  "${core} system-zone up ${tools}"
                  + lib.optionalString (z.configFile != null) " --config ${lib.escapeShellArg z.configFile}"
                  + " ${name}";
                # После любой остановки, и после неудачного старта тоже:
                # туннель удалён, в зоне остаётся один lo.
                ExecStopPost = "${core} system-zone down ${tools} ${name}";
                # При загрузке endpoint может ещё не разрешаться.
                Restart = "on-failure";
                RestartSec = "10s";
              };
            };
          }) cfg.zones
        );
      }

      # --- СЛУЖБЫ В ЗОНЕ (этап 2) ---
      {
        systemd.services = lib.mapAttrs (
          _unit: s:
          consumerDeps s.zone
          // {
            serviceConfig = {
              NetworkNamespacePath = netnsPath s.zone;
              # Без «-»: нет файла — служба не стартует, а не резолвит через хост.
              BindReadOnlyPaths = [ "${resolvPath s.zone}:/etc/resolv.conf" ];
              # Оба — unix-сокеты, а они сквозь сетевые namespace проходят:
              # glibc спрашивает nscd первым, nss-resolve ходит к resolved по
              # varlink, и любой из них ответил бы из сети хоста. «-» — потому
              # что на хосте может не быть ни того, ни другого.
              InaccessiblePaths = [
                "-/run/nscd"
                "-/run/systemd/resolve/io.systemd.Resolve"
              ]
              ++ lib.optional (!s.systemBus) "-/run/dbus/system_bus_socket";
            };
          }
        ) cfg.services;
      }

      # --- NIXOS-КОНТЕЙНЕРЫ В ЗОНЕ (этап 3) ---
      {
        # Сеть — НЕ через containers.<c>.networkNamespace: nspawn входит в
        # чужое сетевое пространство уже из нового user namespace контейнера,
        # а пространство зоны принадлежит user namespace хоста — «Failed to
        # join network namespace: Operation not permitted» при
        # privateUsers = "pick" (проверено в tests/vm-system.nix). Поэтому в
        # зону входит сам systemd, до запуска nspawn (NetworkNamespacePath у
        # container@<c> ниже), а nspawn без сетевых флагов делит сеть, в
        # которой запущен, — сеть зоны. Свой user namespace контейнер получает
        # как обычно, и прав над сетью зоны у его root нет.
        containers = lib.mapAttrs (_c: a: {
          privateUsers = lib.mkDefault "pick";
          extraFlags = [
            # Стартовый скрипт nixpkgs копирует resolv.conf хоста в корень
            # каждого контейнера; поверх него — файл зоны, и nspawn его не трогает.
            "--resolv-conf=off"
            "--bind-ro=${resolvPath a.zone}:/etc/resolv.conf"
          ]
          # Сокет nix-daemon ХОСТА nixpkgs монтирует в каждый контейнер, и любой
          # пользователь там может попросить демон собрать fixed-output
          # деривацию — то есть скачать что угодно из сети хоста, мимо туннеля.
          ++ lib.optional (
            config.nix.enable && (config.nix.daemon.enable or true)
          ) "--inaccessible=/nix/var/nix/daemon-socket";
        }) cfg.containers;

        systemd.services = lib.mapAttrs' (
          c: a:
          lib.nameValuePair "container@${c}" (
            consumerDeps a.zone
            // {
              serviceConfig.NetworkNamespacePath = netnsPath a.zone;
            }
          )
        ) cfg.containers;
      }
    ]
  );
}
