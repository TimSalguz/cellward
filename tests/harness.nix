# Автономная тестовая обвязка: собирает home-manager-конфигурацию с модулем
# cellward БЕЗ flake-инпутов (у flake.nix их нет намеренно). nixpkgs и
# home-manager пинуются в tests/pins.nix — конкретный коммит стабильной ветки с
# явным sha256, сборка воспроизводима и не едет вслед за веткой. Оттуда же пины
# берёт и VM-тест (tests/vm.nix).
#
# Использование:
#   nix-instantiate tests/harness.nix -A activationPackage        # только eval
#   nix-build tests/harness.nix -A scripts.cellward               # адресная сборка
#   nix-instantiate --eval --strict tests/harness.nix -A oldNames -A singleEntry -A keepOnSwitch
#   nix-build tests/harness.nix -A zoneHolder \
#     --argstr username "$(id -un)" --argstr homeDirectory "$HOME"
{
  username ? "runner",
  homeDirectory ? "/home/runner",
  system ? builtins.currentSystem,
}:

let
  pins = import ./pins.nix;
  nixpkgsSrc = pins.nixpkgs;
  homeManagerSrc = pins.home-manager;

  pkgs = import nixpkgsSrc {
    inherit system;
    config = { };
    overlays = [ ];
  };
  inherit (pkgs) lib;

  # Не-flake вход home-manager: modules/default.nix принимает { configuration,
  # pkgs, … } и возвращает { config, options, activationPackage, … }.
  hm = import "${homeManagerSrc}/modules" {
    inherit pkgs;
    configuration =
      { ... }:
      {
        imports = [ ../module ];
        programs.cellward.enable = true;
        home = {
          inherit username homeDirectory;
          # Фиксируем: тестовая конфигурация всегда «свежая», миграций нет.
          stateVersion = "26.05";
        };
      };
  };

  # Скрипты модуля — внутренние let-биндинги, наружу они попадают только через
  # home.packages. Вытаскиваем их оттуда по имени деривации (lib.getName
  # отбрасывает версию: «cellward-0.1.0» → «cellward»), чтобы CI мог собирать
  # каждый адресно, не собирая activationPackage целиком.
  #
  # Список короткий, и это результат: shell в модуле остался ровно четырьмя
  # двухстрочными обёртками над бинарями крейта (у cellward и cellward-gui
  # рядом ещё ссылки-псевдонимы: cw и vpn-zone, vpn-zone-gui). Пикер, шесть
  # GUI-ярлыков, обе песочницы и сам CLI — теперь подкоманды и бинари крейта,
  # а он собирается своим job'ом.
  scriptNames = [
    "cellward"
    "vpn-zone-pick"
    "vpn-zone-sync"
    "cellward-gui"
  ];

  scriptByName =
    name:
    let
      matches = lib.filter (p: lib.getName p == name) hm.config.home.packages;
    in
    if matches == [ ] then
      throw "tests/harness.nix: в home.packages модуля нет скрипта «${name}» — список scriptNames разошёлся с module/default.nix"
    else
      lib.head matches;

  # ExecStart шаблонного юнита vpn-zone@ — строка вида
  # «/nix/store/…/bin/vpn-zone-core zone-holder --ip … --pasta … %i»: держатель
  # переехал в rust-крейт, а пути инструментов подставляет модуль. Берём строку
  # именно отсюда: интерполяция сохраняет ей контекст ВСЕХ store-путей, поэтому
  # обёртка ниже тянет за собой и ip, и pasta, и awg/wg.
  # Тип юнит-опций home-manager коэрсит значение в список (повторяемые ключи
  # ini) — нормализуем обратно в строку.
  # A synthetic CA made at build time — for the declared trust option only; no
  # certificate or key is kept in git.
  testCa = pkgs.runCommand "cellward-test-ca" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p "$out"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=cellward harness CA" \
      -addext "basicConstraints=critical,CA:TRUE" -keyout "$out/ca.key" -out "$out/ca.pem" 2>/dev/null
  '';

  # Every declarative option set (docs/CONTAINERS.md §8): under the new
  # names in hmDeclared, under the old ones in hmOldNames.
  declaredOptions = {
    enable = true;
    defaults = {
      network = "offline";
      container = "own";
    };
    launcher.mode = "picker";
    autostart.unassigned = "offline";
    pathShims.enable = true;
    hermetic = {
      default = true;
      exceptions = [ "agents" ];
    };
    compositorRestriction.enable = true;
    microphone = {
      calls = "yes";
      offline = "no";
      agents = "ask";
    };
    screencast = {
      calls = "yes";
      offline = "no";
      agents = "ask";
    };
    askAgainAfter = "10m";
    audioManager = [ "mixer" ];
    pipewirePolicy = true;
    desktop = {
      windowMenu.key = "Mod+Shift+Z";
      niri = {
        enable = true;
        includeInConfig = true;
      };
      sway.enable = true;
    };
    containers.work = {
      home = "overlay";
      network = "direct";
      apps = [ "firefox" ];
      trust = {
        certificates = [ "${testCa}/ca.pem" ];
        acknowledgeRisk = true;
      };
    };
    containers.dev = {
      apps = [ "org.telegram.desktop" ];
      permissions.paths = [
        "~/.wine"
        "/mnt/games"
      ];
    };
  };

  # The same module with every declarative option set: the eval job
  # instantiates it, so an option that stops evaluating (or an assertion that
  # fires on a valid configuration) is red in CI and not on somebody's switch.
  declaredHome =
    optionRoot:
    import "${homeManagerSrc}/modules" {
      inherit pkgs;
      configuration =
        { ... }:
        {
          imports = [ ../module ];
          programs.${optionRoot} = declaredOptions;
          home = {
            inherit username homeDirectory;
            stateVersion = "26.05";
          };
          # The user's own niri config, written by home-manager as text — what
          # desktop.niri.includeInConfig appends its line to.
          xdg.configFile."niri/config.kdl".text = ''
            binds {
                Mod+Return { spawn "foot"; }
            }
          '';
        };
    };
  hmDeclared = declaredHome "cellward";
  # The names the project had until 2026-09 (programs.vpn-zones): they must
  # still give the same home, with a warning (oldNames below).
  hmOldNames = declaredHome "vpn-zones";

  # A NixOS machine with the NixOS module and home-manager's, evaluated and
  # never built or booted: what the single entry and the old option names do
  # to a system.
  nixos =
    modules:
    import "${nixpkgsSrc}/nixos/lib/eval-config.nix" {
      inherit system;
      modules = [
        ../module/nixos.nix
        "${homeManagerSrc}/nixos"
        {
          fileSystems."/" = {
            device = "/dev/null";
            fsType = "ext4";
          };
          boot.loader.grub.enable = false;
          documentation.enable = false;
          system.stateVersion = "26.05";
          users.users.alice.isNormalUser = true;
          home-manager.useGlobalPkgs = true;
          home-manager.users.alice.home.stateVersion = "26.05";
        }
      ]
      ++ modules;
    };

  # The system tier with most of its options set — once under the new names,
  # once under the old ones (services.vpn-zones, until 2026-09).
  systemOptions = {
    enable = true;
    users = [ "alice" ];
    zones = {
      nl = {
        users = [ "alice" ];
        configFile = "/run/secrets/vpn-nl";
      };
      direct0.kind = "plain";
    };
    services.demo.zone = "nl";
    console = {
      enable = true;
      zone = "nl";
      fallback = "direct0";
    };
    host = {
      nix = "direct0";
      time = "direct0";
      dns = "direct0";
    };
    egress = {
      enable = true;
      mode = "strict";
      allowUsers = [ "alice" ];
      emergency.minutes = 5;
    };
  };
  systemTier =
    root:
    nixos [
      {
        services.${root} = {
          system = systemOptions;
          pipewirePolicy.enable = true;
        };
        services.pipewire.enable = true;
      }
    ];
  systemNew = systemTier "cellward";
  systemOld = systemTier "vpn-zones";

  # The single entry, services.cellward.enable: with the system tier and its
  # egress policy (and the home-manager module imported by hand as well —
  # the same module, taken once), with the defaults it sets overridden, and
  # alone.
  entry = nixos [
    {
      services.cellward = {
        enable = true;
        system = {
          enable = true;
          egress.enable = true;
        };
      };
      services.pipewire.enable = true;
      home-manager.users.alice.imports = [ ../module ];
      users.users.bob.isNormalUser = true;
      home-manager.users.bob = {
        home.stateVersion = "26.05";
        programs.cellward.enable = false;
      };
    }
  ];
  entryOverridden = nixos [
    {
      services.cellward = {
        enable = true;
        system = {
          enable = true;
          egress.enable = true;
          host.nix = null;
          host.time = null;
          amneziawg = false;
        };
      };
    }
  ];
  entryAlone = nixos [ { services.cellward.enable = true; } ];

  # `true`, or a failure that says what went wrong.
  expect = what: ok: if ok then true else throw "tests/harness.nix: ${what}";
  # Every option below a prefix, by its path under it.
  optionPaths =
    depth: opts:
    lib.sort lib.lessThan (
      map (o: lib.concatStringsSep "." (lib.drop depth o.loc)) (lib.collect lib.isOption opts)
    );
  count = x: list: lib.length (lib.filter (y: y == x) list);
  warnsOf = what: config: lib.any (lib.hasInfix what) config.warnings;
  toplevel = machine: builtins.seq machine.config.system.build.toplevel.drvPath true;

  rawExecStart = hm.config.systemd.user.services."vpn-zone@".Service.ExecStart;
  zoneHolderExecLine = if lib.isList rawExecStart then lib.head rawExecStart else rawExecStart;
in
{
  # Полная активация home-manager: инстанцируется в CI как «модуль хотя бы
  # целиком вычисляется». Собирать её не обязательно.
  inherit (hm) activationPackage;

  # Every declarative option set (docs/CONTAINERS.md §8).
  declaredActivation = hmDeclared.activationPackage;

  # The old option names — programs.vpn-zones and services.vpn-zones, the
  # project's until 2026-09 — name every option of the new ones, and give
  # the same home and the same system, with a warning:
  #   nix-instantiate --eval --strict tests/harness.nix -A oldNames
  oldNames = lib.all lib.id [
    (expect "an option of programs.cellward has no old name, or an old name no option" (
      optionPaths 2 hmDeclared.options.programs.cellward
      == optionPaths 2 hmDeclared.options.programs.vpn-zones
    ))
    (expect "programs.vpn-zones gives another home than programs.cellward" (
      hmOldNames.activationPackage.drvPath == hmDeclared.activationPackage.drvPath
    ))
    (expect "programs.vpn-zones does not warn" (warnsOf "programs.vpn-zones" hmOldNames.config))
    (expect "programs.cellward warns of an old name" (!warnsOf "vpn-zones" hmDeclared.config))
    (expect "an option of services.cellward.system has no old name, or an old name no option" (
      optionPaths 3 systemNew.options.services.cellward.system
      == optionPaths 3 systemNew.options.services.vpn-zones.system
    ))
    (expect "services.vpn-zones.pipewirePolicy.enable has no new name" (
      systemOld.config.services.cellward.pipewirePolicy.enable
    ))
    (expect "services.vpn-zones gives another system than services.cellward" (
      systemOld.config.system.build.toplevel.drvPath == systemNew.config.system.build.toplevel.drvPath
    ))
    (expect "services.vpn-zones does not warn" (warnsOf "services.vpn-zones" systemOld.config))
    (expect "services.cellward warns of an old name" (!warnsOf "vpn-zones" systemNew.config))
  ];

  # What the single entry turns on, what it leaves to an explicit choice, and
  # that a machine with it evaluates:
  # An update leaves running zones alone: home-manager's sd-switch keeps a
  # running zone and the broker's socket as they are, and NixOS's switch
  # does not restart a system zone's namespace or its tunnel — otherwise the
  # programs in a zone lose the network on every update.
  #   nix-instantiate --eval --strict tests/harness.nix -A keepOnSwitch
  keepOnSwitch =
    let
      u = hmDeclared.config.systemd.user;
      s = entry.config.systemd.services;
    in
    lib.all lib.id [
      (expect "a running zone is restarted by a switch" (
        u.services."vpn-zone@".Unit.X-SwitchMethod == "keep-old"
      ))
      (expect "the broker's socket is made anew by a switch" (
        u.sockets.vpn-zone-broker.Unit.X-SwitchMethod == "keep-old"
      ))
      (expect "a system zone's tunnel is restarted by a switch" (!s."vpn-zone-system@".restartIfChanged))
      (expect "a system zone's namespace is restarted by a switch" (
        !s."vpn-zone-system-ns@".restartIfChanged
      ))
    ];

  #   nix-instantiate --eval --strict tests/harness.nix -A singleEntry
  singleEntry =
    let
      e = entry.config;
      o = entryOverridden.config;
      a = entryAlone.config;
    in
    lib.all lib.id [
      (expect "the kernel modules of a zone are not loaded" (
        lib.all (m: count m e.boot.kernelModules == 1) [
          "amneziawg"
          "wireguard"
          "tun"
          "nf_tables"
        ]
        && count "amneziawg" a.boot.kernelModules == 1
        && lib.length e.boot.extraModulePackages == 1
        && lib.length a.boot.extraModulePackages == 1
      ))
      (expect "system.amneziawg = false still loads amneziawg" (
        count "amneziawg" o.boot.kernelModules == 0 && o.boot.extraModulePackages == [ ]
      ))
      (expect "the PipeWire policy is not on with WirePlumber, or on without it" (
        e.services.cellward.pipewirePolicy.enable && !a.services.cellward.pipewirePolicy.enable
      ))
      (expect "the home-manager module is not on for a home-manager user" (
        e.home-manager.users.alice.programs.cellward.enable
        && !e.home-manager.users.bob.programs.cellward.enable
        && a.home-manager.users.alice.programs.cellward.enable
      ))
      (expect "with the egress policy, the Nix daemon and the clock do not go through direct0" (
        e.services.cellward.system.host.nix == "direct0"
        && e.services.cellward.system.host.time == "direct0"
        && e.services.cellward.system.zones.direct0.kind == "plain"
      ))
      (expect "an explicit host.nix/host.time does not win over the single entry" (
        o.services.cellward.system.host.nix == null
        && o.services.cellward.system.host.time == null
        && !(o.services.cellward.system.zones ? direct0)
      ))
      (expect "the single entry turned on what stays a choice" (
        !a.services.cellward.system.enable
        && !a.services.cellward.system.egress.enable
        && a.services.cellward.system.host.nix == null
        && e.services.cellward.system.host.dns == null
        && !e.services.cellward.system.console.enable
      ))
      (toplevel entry)
      (toplevel entryOverridden)
      (toplevel entryAlone)
    ];

  # The window menu's key and our windows' rule as the compositors read them:
  # niri validates its config with the include resolved, sway checks its
  # file. The store paths inside are cut loose — validating a line does not
  # need the binary it names built.
  #   nix-build tests/harness.nix -A compositorSnippets
  compositorSnippets =
    let
      files = hmDeclared.config.xdg.configFile;
      text = name: builtins.unsafeDiscardStringContext files.${name}.text;
    in
    pkgs.runCommand "cellward-compositor-snippets"
      {
        nativeBuildInputs = [
          pkgs.niri
          # The package `sway` wraps the binary in dbus-run-session.
          pkgs.sway-unwrapped
        ];
        niriConfig = text "niri/config.kdl";
        niriSnippet = text "niri/vpn-zones.kdl";
        swaySnippet = text "sway/vpn-zones.conf";
        passAsFile = [
          "niriConfig"
          "niriSnippet"
          "swaySnippet"
        ];
      }
      ''
        mkdir -p niri
        cp "$niriConfigPath" niri/config.kdl
        cp "$niriSnippetPath" niri/vpn-zones.kdl
        cat niri/config.kdl niri/vpn-zones.kdl
        grep -q '^include "vpn-zones.kdl"$' niri/config.kdl
        grep -q 'Mod+Shift+Z hotkey-overlay-title=' niri/vpn-zones.kdl
        niri validate -c niri/config.kdl
        cat "$swaySnippetPath"
        grep -q '^bindsym Mod4+Shift+z exec /nix/store/.*/bin/cellward window-menu$' "$swaySnippetPath"
        # --validate still makes a backend: a headless one, drawn in software.
        export XDG_RUNTIME_DIR=$TMPDIR WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1
        sway --validate --config "$swaySnippetPath"
        touch $out
      '';

  # Каждый скрипт — отдельным атрибутом: nix-build tests/harness.nix -A scripts.<имя>
  scripts = lib.genAttrs scriptNames scriptByName // {
    recurseForDerivations = true;
  };

  # Строка ExecStart юнита vpn-zone@ (для диагностики):
  #   nix-instantiate --eval tests/harness.nix -A zoneHolderExec
  zoneHolderExec = zoneHolderExecLine;

  # Запускаемая обёртка над держателем зоны: `zone-holder <имя-зоны>` делает то
  # же, что systemd-юнит vpn-zone@<имя>, но без systemd — на CI-раннере юнит не
  # установлен, а смоук-тесту зону поднимать надо.
  #
  # Строка подставляется БЕЗ кавычек намеренно: в ней несколько слов (бинарь,
  # подкоманда и флаги с путями), и словоделение bash — ровно то, что нужно;
  # пробелов внутри store-путей не бывает. Убираем из неё «%i» и подставляем
  # имя зоны своим аргументом.
  zoneHolder = pkgs.writeShellScriptBin "zone-holder" ''
    exec ${lib.replaceStrings [ " %i" ] [ "" ] zoneHolderExecLine} "''${1:?нужно имя зоны}"
  '';

  # Инструменты для смоук-теста — теми же версиями, что использует модуль.
  # Именно buildEnv, а не отдельные пакеты: util-linux и iproute2 многовыходные,
  # и `nix-build -o link` даёт ссылку на дефолтный output, в котором bin/ может
  # не быть — смоук на раннере так и упал («util-linux/bin/unshare: No such
  # file»). buildEnv собирает bin/ всех инструментов в один выход.
  smokeTools = pkgs.buildEnv {
    name = "cellward-smoke-tools";
    paths = with pkgs; [
      wireguard-tools
      iproute2
      util-linux
      passt
      # Второй эшелон (docs/LEAK-MODEL.md): смоуку нужен nft, чтобы прочитать
      # `nft list ruleset` ВНУТРИ обоих namespace зоны. Сама зона получает свой
      # путь к nft флагом ExecStart, отсюда — только читалка.
      nftables
      # Не для самой зоны: coreutils нужен КОМАНДЕ ВНУТРИ песочницы ФС — там
      # своя /tmp и никакого /usr, поэтому `ls` обязан быть store-путём. Раньше
      # он грепался из текста shell-скрипта vpn-zone, а тот теперь бинарь.
      coreutils
    ];
    pathsToLink = [ "/bin" ];
  };

  # Обвязка для смоука ЗОНЫ OPENCONNECT — отдельным атрибутом, а не внутри
  # smokeTools: замыкание ocserv никому, кроме этой части теста, не нужно.
  #
  # Что зачем:
  #   • ocserv — настоящий сервер AnyConnect, поднимается на раннере под sudo
  #     (ему нужен свой tun в сети хоста) с самоподписанным сертификатом,
  #     который генерируется на лету. В git ни ключей, ни сертификатов;
  #   • openconnect — тот же клиент, что поедет пользователю. Смоук зовёт его
  #     ОДИН раз до создания зоны, чтобы спросить у него самого отпечаток
  #     сертификата («--servercert pin-sha256:…» он печатает в подсказке):
  #     считать отпечаток своими руками значит однажды разойтись с ним в
  #     формате;
  #   • openssl — сертификат, ключ и crypt-хеш пароля для plain-аутентификации
  #     ocserv (формат файла — username:группы:crypt(3)).
  ocTools = pkgs.buildEnv {
    name = "cellward-oc-tools";
    paths = with pkgs; [
      ocserv
      openconnect
      openssl
    ];
    pathsToLink = [ "/bin" ];
  };

  # Окружение для rust-джоба CI: `nix-shell tests/harness.nix -A rustShell`.
  # Именно отсюда, а не `nix-shell -p`: у раннера нет канала <nixpkgs>
  # (install-nix-action его не ставит), а главное — компилятор и clippy
  # пинуются тем же nixpkgs, что и всё остальное, и CI не краснеет сам по
  # себе от обновления линтера в unstable.
  rustShell = pkgs.mkShell {
    packages = with pkgs; [
      cargo
      rustc
      clippy
      rustfmt
      pkg-config
      libseccomp
    ];
    # The font of the window title (rust/src/wl_title.rs), as package.nix
    # builds it in: the tests draw the text with it.
    VPN_ZONE_FRAME_FONT = "${pkgs.dejavu_fonts.minimal}/share/fonts/truetype/DejaVuSans.ttf";
  };
}
