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
    "--pasta ${pkgs.passt}/bin/pasta"
  ];

  # Шаблоны: зона — экземпляр, так что зону можно добавить и без пересборки
  # (vpn-zone-sys --add), а объявленные отличаются только настройками в /etc.
  nsUnit = zone: "vpn-zone-system-ns@${zone}";
  holderUnit = zone: "vpn-zone-system@${zone}";
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
      kind = lib.mkOption {
        type = lib.types.enum [
          "tunnel"
          "plain"
        ];
        default = "tunnel";
        description = ''
          `tunnel`: WireGuard/AmneziaWG, the config from `configFile` or the
          state directory. `plain`: no tunnel — out through the host's own
          network by pasta, not encrypted by the zone, but a namespace of its
          own with its own resolvers and nothing of the host's. For the TTY
          console when the VPN cannot come up, and for programs that have to
          go out directly once the host has no network of its own (`egress`).
        '';
      };
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
      users = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "alice" ];
        description = ''
          Users who may run console programs in this zone with
          `vpn-zone-sys <name> -- <command>`. The program runs as the user,
          with the zone's network and resolvers, without the session's sockets
          and with no way to gain privileges. Empty: nobody.
        '';
      };
      systemBus = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Leave the host's system bus reachable to programs run with
          `vpn-zone-sys`. Off by default for the same reason as for services:
          systemd-resolved answers name lookups over it, around the tunnel.
        '';
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

  # Кто вообще ходит через посредника: у сокета группа vpn-zones, а список
  # по зонам посредник проверяет сам.
  runUsers = lib.unique (
    cfg.users ++ lib.concatMap (z: z.users) (lib.attrValues cfg.zones)
  );

  # pasta одной или нескольких простых зон: системный пользователь, а не root и
  # не nobody — политика хоста пропускает системных, и этого знает по имени.
  plainUser = "vpn-zones-plain";

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

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = ''
        Users who may add system zones on the spot (`vpn-zone-sys --add`) and
        see their state; a zone's own `users` may use it. Everybody listed here
        or in any zone's `users` is in the group `vpn-zones`.
      '';
    };

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

    console = {
      enable = lib.mkEnableOption ''
        the TTY console (docs/SYSTEM.md §7a): logging in on a text console
        lands in a small menu with a network already — a terminal in `zone`
        with one key, the plain `fallback` zone when the VPN does not come up,
        the admin tool, the emergency key, the plain console. For the users of
        `zone`; everybody else gets the ordinary login'';
      zone = lib.mkOption {
        type = lib.types.str;
        example = "nl";
        description = "The system zone the console's terminal runs in. Its `users` get the console.";
      };
      fallback = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "direct";
        description = "A plain zone offered when `zone` has no live tunnel.";
      };
      admin = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.submodule {
            options = {
              command = lib.mkOption {
                type = lib.types.str;
                description = "Run on the host, as the user.";
              };
              label = lib.mkOption {
                type = lib.types.str;
                description = "What the menu calls it.";
              };
            };
          }
        );
        default = null;
        example = lib.literalExpression ''{ command = "nix_cm --tui"; label = "Настройки и откат"; }'';
        description = "An admin tool behind the `n` key.";
      };
    };

    egress = {
      enable = lib.mkEnableOption ''
        the host egress policy (docs/SYSTEM.md §9): a user's program outside
        every zone does not reach the network. Root, system users, the uplinks
        of user zones, system zones and everything inside a zone are not
        affected'';
      mode = lib.mkOption {
        type = lib.types.enum [
          "audit"
          "enforce"
        ];
        default = "audit";
        description = ''
          `audit` logs what would be refused and lets it through — watch the
          kernel log for `vpn-zones-egress:` before switching; `enforce`
          refuses it.
        '';
      };
      allowUsers = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "alice" ];
        description = "Users whose own programs still go out directly — for moving over one person at a time.";
      };
      allowGroups = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ "nixbld" ];
        description = "Groups whose programs go out directly. `nixbld`: builds that fetch.";
      };
      emergency = {
        minutes = lib.mkOption {
          type = lib.types.ints.positive;
          default = 15;
          description = "How long `vpn-zones-egress-open.service` lifts the policy before it puts it back.";
        };
        group = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = "wheel";
          description = "Members may start and stop `vpn-zones-egress-open.service` without a password; this turns polkit on. `null`: root only.";
        };
      };
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
          ++ lib.mapAttrsToList (name: z: {
            assertion = z.kind != "plain" || z.configFile == null;
            message = "services.vpn-zones.system.zones.${name}: a plain zone has no tunnel, so no configFile.";
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

        users.groups.vpn-zones.members = runUsers;
        # Всегда: простую зону можно добавить и на ходу.
        users.users.${plainUser} = {
          isSystemUser = true;
          group = plainUser;
          description = "vpn-zones pasta of plain system zones";
        };
        users.groups.${plainUser} = { };

        # Список для `vpn-zone status --json` (system_networks), и по зоне —
        # кто может запускать в ней программы (посредник, rust/src/sysrun.rs).
        environment.etc = {
          "vpn-zones/system-zones".text = lib.concatMapStrings (name: name + "\n") (
            lib.attrNames cfg.zones
          );
        }
        // lib.mapAttrs' (
          name: z:
          lib.nameValuePair "vpn-zones/system-zones.d/${name}/users" {
            text = lib.concatMapStrings (u: u + "\n") z.users;
          }
        ) cfg.zones
        // lib.mapAttrs' (
          name: _:
          lib.nameValuePair "vpn-zones/system-zones.d/${name}/system-bus" { text = "yes\n"; }
        ) (lib.filterAttrs (_: z: z.systemBus) cfg.zones)
        // lib.mapAttrs' (
          name: z: lib.nameValuePair "vpn-zones/system-zones.d/${name}/kind" { text = z.kind + "\n"; }
        ) cfg.zones
        // lib.mapAttrs' (
          name: z: lib.nameValuePair "vpn-zones/system-zones.d/${name}/config" { text = z.configFile + "\n"; }
        ) (lib.filterAttrs (_: z: z.configFile != null) cfg.zones);

        boot.extraModulePackages = lib.mkIf cfg.amneziawg [ config.boot.kernelPackages.amneziawg ];
        boot.kernelModules = lib.mkIf cfg.amneziawg [ "amneziawg" ];

        # Каталог запуска зоны — 2750 root:vpn-zones: группа читает состояние,
        # а новые файлы наследуют группу от setgid-каталога.
        systemd.tmpfiles.rules = [
          "d /run/vpn-zones 0755 root root -"
          "d /run/vpn-zones/system 0755 root root -"
          "d /var/lib/vpn-zones 0755 root root -"
          # 0755: имена и виды зон видны их пользователям; сами конфиги —
          # 0600 root.
          "d /var/lib/vpn-zones/system 0755 root root -"
        ]
        ++ lib.concatLists (
          lib.mapAttrsToList (name: _: [
            "d /run/vpn-zones/system/${name} 2750 root vpn-zones -"
            "d /var/lib/vpn-zones/system/${name} 0755 root root -"
          ]) cfg.zones
        );

        # Держатель сам читает настройки зоны: объявленной — из /etc, добавленной
        # на ходу — из /var/lib/vpn-zones/system/<имя>/. Юниту нужно одно имя.
        systemd.services."vpn-zone-system-ns@" = {
          description = "vpn-zones: network namespace of the system zone %i";
          restartIfChanged = false;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${core} system-zone ns-up ${tools} %i";
            ExecStop = "${core} system-zone ns-down ${tools} %i";
          };
        };
        systemd.services."vpn-zone-system@" = {
          description = "vpn-zones: the way out of the system zone %i";
          bindsTo = [ "vpn-zone-system-ns@%i.service" ];
          after = [
            "vpn-zone-system-ns@%i.service"
            "network-online.target"
          ];
          wants = [ "network-online.target" ];
          serviceConfig = {
            # READY=1 — после настройки туннеля и resolv.conf зоны: всё,
            # что идёт следом, стартует уже с сетью, а не с одним lo.
            Type = "notify";
            ExecStart = "${core} system-zone up ${tools} %i";
            # После любой остановки, и после неудачного старта тоже:
            # туннель удалён, в зоне остаётся один lo.
            ExecStopPost = "${core} system-zone down ${tools} %i";
            # При загрузке endpoint может ещё не разрешаться.
            Restart = "on-failure";
            RestartSec = "10s";
          };
        };
        systemd.targets.multi-user.wants = map (name: "${holderUnit name}.service") (
          lib.attrNames (lib.filterAttrs (_: z: z.autoStart) cfg.zones)
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
              BindReadOnlyPaths = [
                "${resolvPath s.zone}:/etc/resolv.conf"
                # hosts: files dns — ни один модуль NSS, кроме обычного
                # резолвера, имя не получит (страховка на весь класс, как у
                # пользовательских зон).
                "/etc/netns/vz-${s.zone}/nsswitch.conf:/etc/nsswitch.conf"
              ];
              # Оба — unix-сокеты, а они сквозь сетевые namespace проходят:
              # glibc спрашивает nscd первым, nss-resolve ходит к resolved по
              # varlink, и любой из них ответил бы из сети хоста. «-» — потому
              # что на хосте может не быть ни того, ни другого.
              InaccessiblePaths = [
                "-/run/nscd"
                "-/run/systemd/resolve/io.systemd.Resolve"
                # nss-mdns: имя на .local ушло бы в локальную сеть хоста.
                "-/run/avahi-daemon"
              ]
              ++ lib.optional (!s.systemBus) "-/run/dbus/system_bus_socket";
            };
          }
        ) cfg.services;
      }

      # --- ПРОГРАММЫ ПОЛЬЗОВАТЕЛЕЙ В ЗОНЕ (этап 4, docs/SYSTEM.md §7) ---
      # Войти в пространство зоны без root нельзя, поэтому входит посредник:
      # по юниту на каждый запуск (Accept=yes), кто спрашивает — от ядра,
      # команда — уже от имени пользователя и с NO_NEW_PRIVS.
      {
        systemd.sockets.vpn-zone-sysrun = {
          description = "vpn-zones: programs of users in system zones";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenSequentialPacket = "/run/vpn-zones/sysrun.sock";
            SocketMode = "0660";
            SocketGroup = "vpn-zones";
            Accept = true;
            MaxConnections = 64;
          };
        };
        systemd.services."vpn-zone-sysrun@" = {
          description = "vpn-zones: a program in a system zone";
          serviceConfig = {
            ExecStart = "${core} system-run-service";
            StandardInput = "socket";
            StandardOutput = "journal";
            StandardError = "journal";
            # «Добавить зону» и «поднять зону» — systemctl от root.
            Environment = "VPN_ZONE_SYSTEMCTL=${config.systemd.package}/bin/systemctl";
            # Войти в пространство и смонтировать своё (SYS_ADMIN), стать
            # пользователем (SETUID, SETGID), погасить его программу, когда
            # клиент ушёл (KILL). Больше ничего.
            CapabilityBoundingSet = [
              "CAP_SYS_ADMIN"
              "CAP_SETUID"
              "CAP_SETGID"
              "CAP_KILL"
            ];
          };
        };
        environment.systemPackages = [
          (pkgs.writeShellScriptBin "vpn-zone-sys" ''
            exec ${core} system-run "$@"
          '')
        ];
      }

      # --- ПУЛЬТ TTY (docs/SYSTEM.md §7a) ---
      # Вход на текстовой консоли: сразу меню с сетью. Решает, показываться ли,
      # сама программа (только VT, только вне зоны, только пользователям зоны),
      # а при любой ошибке уступает обычной оболочке — запереть снаружи пульт
      # не может.
      (lib.mkIf cfg.console.enable {
        assertions = [
          {
            assertion = cfg.zones ? ${cfg.console.zone} && cfg.zones.${cfg.console.zone}.users != [ ];
            message = "services.vpn-zones.system.console.zone = \"${cfg.console.zone}\" has to be a declared zone with users.";
          }
          {
            assertion =
              cfg.console.fallback == null
              || (cfg.zones ? ${cfg.console.fallback} && cfg.zones.${cfg.console.fallback}.kind == "plain");
            message = "services.vpn-zones.system.console.fallback has to be a declared plain zone.";
          }
        ];
        environment.etc."vpn-zones/console".text =
          "zone=${cfg.console.zone}\n"
          + lib.optionalString (cfg.console.fallback != null) "fallback=${cfg.console.fallback}\n"
          + lib.optionalString (cfg.console.admin != null) (
            "admin=${cfg.console.admin.command}\nadmin-label=${cfg.console.admin.label}\n"
          );
        environment.systemPackages = [
          (pkgs.writeShellScriptBin "vpn-zone-console" ''
            exec ${core} console "$@"
          '')
        ];
        # Один раз на вход (оболочка в зоне — тоже оболочка входа) и только в
        # интерактивной: display manager запускает сеанс через `bash -l -c …`,
        # часто прямо на VT, и встать перед композитором пульт не должен.
        environment.loginShellInit = ''
          case $- in
            *i*)
              if [ -z "''${VPN_ZONE_CONSOLE-}" ]; then
                export VPN_ZONE_CONSOLE=1
                ${core} console --login
              fi
              ;;
          esac
        '';
      })

      # --- ХОСТ БЕЗ СЕТИ (этап 5, docs/SYSTEM.md §9) ---
      # Своя таблица nftables и свой юнит: откат поколения снимает политику
      # вместе со всем остальным. Признак — владелец сокета, а не cgroup:
      # наборы cgroup пустеют при каждой перезагрузке фаервола.
      (lib.mkIf cfg.egress.enable (
        let
          e = cfg.egress;
          nft = "${pkgs.nftables}/bin/nft";
          # Запрет — из файла, собранного вместе с системой, и грузит его сам
          # nft. Наша программа только ДОПИСЫВАЕТ разрешения (выходы
          # пользовательских зон, названных людей): упадёт она — хост станет
          # закрытее, а не открытым. `nixbld` известен при сборке — он в файле.
          nixbldInFile = builtins.elem "nixbld" e.allowGroups;
          rules = pkgs.runCommand "vpn-zones-egress.nft" { } (
            "${core} egress print"
            + lib.optionalString (e.mode == "enforce") " --enforce"
            + lib.optionalString nixbldInFile " --gid ${toString config.ids.gids.nixbld}"
            + " > $out"
          );
          allow = lib.concatStringsSep " " (
            [ "${core} egress allow --nft ${nft}" ]
            ++ map (u: "--user ${lib.escapeShellArg u}") e.allowUsers
            ++ map (g: "--group ${lib.escapeShellArg g}") (lib.remove "nixbld" e.allowGroups)
          );
          # «-»: разрешения не добавились — политика стоит строже, а не падает.
          apply = [
            "${nft} -f ${rules}"
            "-${allow}"
          ];
          # Фаервол NixOS, стирающий ВСЕ таблицы при перезагрузке, стёр бы и
          # нашу — тогда политика перечитывается вслед за ним.
          flushes = config.networking.nftables.enable && config.networking.nftables.flushRuleset;
        in
        {
          systemd.services.vpn-zones-egress = {
            description = "vpn-zones: the host egress policy (${e.mode})";
            # Путь спасения без единого нашего бинарника: `vpnzones.egress=off`
            # в строке ядра (в меню загрузки — `e`) — и политика не поднимается.
            unitConfig.ConditionKernelCommandLine = "!vpnzones.egress=off";
            wantedBy = [ "multi-user.target" ];
            before = [ "network-pre.target" ];
            wants = [ "network-pre.target" ];
            after = [ "nftables.service" ];
            partOf = lib.optional flushes "nftables.service";
            unitConfig.ReloadPropagatedFrom = lib.optional flushes "nftables.service";
            reloadIfChanged = true;
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              ExecStart = apply;
              ExecReload = apply;
              ExecStop = "${nft} destroy table inet vpnzones_egress";
            };
          };

          # Аварийный ключ: таблица остаётся, ограничение снимается на
          # e.emergency.minutes и возвращается само — и по истечении, и при
          # остановке юнита.
          systemd.services.vpn-zones-egress-open = {
            description = "vpn-zones: the host egress policy lifted for ${toString e.emergency.minutes} minutes";
            serviceConfig = {
              Type = "simple";
              # Сам nft, без vpn-zone-core: ключ должен повернуться и тогда,
              # когда сломано всё наше.
              ExecStartPre = "${nft} destroy table inet vpnzones_egress";
              ExecStart = "${pkgs.coreutils}/bin/sleep ${toString (e.emergency.minutes * 60)}";
              ExecStopPost = apply;
            };
          };

          # Без polkit правило ниже никого не пустит, а в NixOS он выключен по
          # умолчанию. Явный `security.polkit.enable = false` здесь даст
          # конфликт определений — это и есть выбор: ключ группе или без polkit
          # (emergency.group = null, ключ только у root).
          security.polkit.enable = lib.mkIf (e.emergency.group != null) true;
          security.polkit.extraConfig = lib.mkIf (e.emergency.group != null) ''
            polkit.addRule(function(action, subject) {
              if (action.id == "org.freedesktop.systemd1.manage-units" &&
                  action.lookup("unit") == "vpn-zones-egress-open.service" &&
                  (action.lookup("verb") == "start" || action.lookup("verb") == "stop") &&
                  subject.isInGroup("${e.emergency.group}")) {
                return polkit.Result.YES;
              }
            });
          '';
        }
      ))

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
