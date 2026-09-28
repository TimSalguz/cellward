# CELLWARD (прежнее имя — vpn-zones): сетевые «контейнеры» с VPN, создаваемые
# и управляемые ИЗ-ПОД ПОЛЬЗОВАТЕЛЯ.
#
# ЧТО ЭТО ДАЁТ. Зона — это отдельное сетевое пространство с поднятым в нём
# туннелем. Приложение, запущенное «в зоне», ходит в сеть только через её VPN;
# всё остальное на машине этого не замечает. Зон может быть сколько угодно и
# каждая со своим конфигом: «Chromium (nl)», «Telegram (ru)» — параллельно.
#
# ЧЕМ ОТЛИЧАЕТСЯ ОТ ОБЫЧНЫХ ОБВЯЗОК НАД netns. Те требуют root и знают ровно один
# namespace, прописанный в системной конфигурации. Здесь root не
# нужен нигде: ни на создание зоны, ни на запуск. Добавление нового VPN — это не
# пересборка системы, а ярлык в лаунчере и файлпикер.
#
# ПОЧЕМУ ЭТО ВООБЩЕ ВОЗМОЖНО БЕЗ ROOT (проверено на niri и KWin):
#   • непривилегированные user namespace разрешены ядром;
#   • /etc/subuid выдаёт пользователю диапазон дополнительных uid — из него берётся «root»
#     внутри зоны, и newuidmap имеет на это cap_setuid;
#   • ядерный модуль amneziawg разрешает создавать интерфейс внутри такого
#     namespace — то есть туннель настоящий, не userspace-эмуляция;
#   • выход зоны наружу даёт pasta (passt) — пользовательский сетевой стек,
#     тот же, на котором работает rootless-podman.
#
# УСТРОЙСТВО (ключевой момент — двойной маппинг uid). Всё это делает
# `vpn-zone-core zone-holder <имя>` (rust/src/zone.rs), его запускает юнит:
#   user namespace: 0→<subuid> и <uid>→<uid>, внутри setuid 0
#     ├── net+mount namespace ─ АПЛИНК: pasta, выход наружу и UDP-сокет туннеля;
#     │                         здесь awg0 создаётся и сразу переезжает вниз
#     ├── pasta --netns <аплинк> ─ выход в интернет
#     └── net+mount namespace ─ ЗОНА ПРИЛОЖЕНИЙ: только lo и awg0, маршруты в
#                               туннель, свой resolv.conf — сюда входит nsenter
# ДВА namespace, а не один, и это главное свойство безопасности: у программ нет
# ни одного интерфейса, кроме туннеля, поэтому утечка невозможна не потому, что
# запрещена правилом, а потому, что пути не существует — ни в LAN, ни мимо VPN,
# ни для какого семейства протоколов. Держится на свойстве WireGuard: UDP-сокет
# остаётся в том namespace, где интерфейс был создан. Подробности —
# docs/LEAK-MODEL.md.
# Внутри мы uid 0 — иначе ядро не даст создать интерфейс (capabilities теряются
# при execve, если uid не нулевой; проверено, с identity-маппингом CapEff=0).
# Но uid пользователя отображён ВТОРЫМ диапазоном, поэтому приложение, вошедшее в
# зону через nsenter --preserve-credentials, работает под твоим настоящим uid и
# видит $HOME как обычно. Ровно то же делает podman в режиме keep-id.
#
# КАК ЭТО ВЫГЛЯДИТ В ЛАУНЧЕРЕ. По умолчанию (режим picker) ярлык у программы
# остаётся ОДИН, но при запуске спрашивает, в какой сети её пустить: прямой
# интернет, без сети, или любая из зон. Выбранное запоминается, а пунктом
# «Всегда: …» закрепляется навсегда — тогда диалога больше не будет. Сбросить
# закрепление можно ярлыком «Сбросить сети программ» (у одной программы или у
# всех) либо командой `cellward forget`.
#
# Незнакомая программа по умолчанию предлагает вариант «Без сети» — это и есть
# политика «интернет не выдаётся, пока его явно не дали». Поменять:
# `cellward default unconfined`. Кому больше нравится прежний вид — «Firefox (nl)»
# отдельным ярлыком на каждую зону — включается `cellward mode per-zone`
# (или both, чтобы работало и то, и другое).
#
# ЧЕГО ЭТО НЕ ДЕЛАЕТ. Зона изолирует ТОЛЬКО сеть. Файловая система, буфер обмена,
# композитор, dbus — общие с хостом. Для недоверенных программ нужен ещё
# контейнер ФС и вложенный композитор — это следующий слой, здесь его нет.
#
# ГРАБЛЯ, О КОТОРОЙ НАДО ПОМНИТЬ ПРИ СОЗДАНИИ ЗОН. Один и тот же приватный ключ
# нельзя держать поднятым дважды: сервер помнит для ключа ровно один endpoint, и
# второе соединение перебивает первое — оба начинают рваться. Поэтому НЕ поднимай
# зону из того же конфига, который уже поднят системным туннелем, и не используй
# один файл для двух зон. Нужны параллельные зоны —
# нужны разные ключи (в Amnezia это отдельная конфигурация на каждое устройство).
{
  config,
  lib,
  pkgs,
  ...
}:

let
  stateDir = "${config.home.homeDirectory}/.local/state/vpn-zones";
  # Профили (контейнеры данных) намеренно вне каталога зон: зону можно удалить,
  # когда VPN заблокировали, а настроенное в профиле окружение должно пережить
  # это и открыться в другой сети.
  #
  # Путь именно в .local/state, и это НЕ вкусовщина. Профиль накрывает своим
  # слоем .config, .local/share, .cache, .mozilla, .pki — а верхний слой
  # overlayfs не может находиться на overlayfs. Пока хранилище лежало в
  # .local/share, первые два каталога монтировались, а на .cache и дальше ядро
  # отвечало EINVAL: их upperdir оказывался уже накрыт предыдущим слоем.
  # .local/state в этот список не входит, поэтому конфликта нет.
  profilesDir = "${config.home.homeDirectory}/.local/state/vpn-profiles";

  # Инструменты, к которым обращаются скрипты. Абсолютные пути, потому что часть
  # кода исполняется внутри namespace, где PATH может быть каким угодно.
  iproute = "${pkgs.iproute2}/bin/ip";
  awg = "${pkgs.amneziawg-tools}/bin/awg";
  wg = "${pkgs.wireguard-tools}/bin/wg";
  # pasta with a patch: a TCP connection it cannot bind to the zone's outbound
  # interface is reset, not connected by the host's routes (review 2026-09-25,
  # patches/passt-bind-outbound-fatal.pl).
  passtPatched = pkgs.passt.overrideAttrs (old: {
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.perl ];
    postPatch = (old.postPatch or "") + ''
      perl ${./patches/passt-bind-outbound-fatal.pl} < tcp.c > tcp.c.new
      mv tcp.c.new tcp.c
    '';
  });
  pasta = "${passtPatched}/bin/pasta";
  # passt из того же пакета: мост, которым зона везёт экземпляр контейнера
  # (rust/src/bridge.rs, этап 2 контейнерного дизайна, 2026-09-27), —
  # `passt --fd` в сети приложений зоны на каждый экземпляр.
  passtBin = "${passtPatched}/bin/passt";
  # Второй эшелон герметичности (docs/LEAK-MODEL.md): фаерволл в обоих
  # namespace зоны. Зовёт его только держатель зоны, поэтому путь идёт флагом
  # ExecStart, как ip/awg/wg/pasta, а не манифестом.
  nft = "${pkgs.nftables}/bin/nft";
  # Второй тип зоны — [OpenConnect] (Cisco AnyConnect/ocserv, а через
  # --protocol ещё GlobalProtect и Pulse). Клиент работает В АПЛИНКЕ, его tun
  # переезжает в зону приложений; путь идёт флагом ExecStart, как ip/awg/wg/
  # pasta/nft, потому что зовёт его только держатель зоны.
  #
  # Штатный vpnc-script сюда НЕ ставится намеренно: --script держателя — это
  # наш же vpn-zone-core oc-script, и подменить его конфигом зоны нельзя
  # (белый список Args=, rust/src/openconnect.rs). Обычный vpnc-script
  # настраивал бы сеть ХОСТА.
  openconnect = "${pkgs.openconnect}/bin/openconnect";
  notify = "${pkgs.libnotify}/bin/notify-send";
  kdialog = "${pkgs.kdePackages.kdialog}/bin/kdialog";
  # Фильтр сессионной шины с одной правкой: `--own=ИМЯ-*` разрешает ЗАНЯТЬ имя
  # ИМЯ-<суффикс> и больше ничего (ни видеть, ни говорить с чужими такими именами);
  # `--own=ИМЯ.*` — то же для ИМЯ.<имя> (MPRIS-плееры: у апстрима это OWN на всё
  # поддерево, то есть разговор с целым соединением любого хостового плеера).
  # Нужна значкам трея: Electron и Qt регистрируют их под
  # org.kde.StatusNotifierItem-<pid>-<n> (нынешний Electron — под
  # org.freedesktop.StatusNotifierItem-<pid>-<n>), а шаблоны xdg-dbus-proxy бывают только
  # вида org.kde.* — а занять любое org.kde.* значит занять и имя KWallet.
  dbusProxy = pkgs.xdg-dbus-proxy.overrideAttrs (old: {
    patches = (old.patches or [ ]) ++ [ ./patches/xdg-dbus-proxy-own-prefix.patch ];
  });

  # --- ЧАСТЬ 0: RUST-ЯДРО ---
  # Здесь ЗАКОНЧИЛСЯ переезд ядра на Rust (ROADMAP M1). Первым переехало то,
  # чего в bash нет в принципе: BPF-фильтр системных вызовов для песочницы —
  # программу для ядра умеет собрать только код (libseccomp). Следом переехали
  # оба бывших python-скрипта: наложение слоёв профиля при запуске программы и
  # генератор .desktop-ярлыков. Затем — ограничитель доступа к композитору,
  # он же бывшая программа на C (module/wl-sandbox.c): создаёт помеченный
  # wayland-сокет, после чего композитор перестаёт выдавать клиенту протоколы
  # слежки. Ни Python, ни C в проекте больше нет.
  #
  # Затем переехал ЖИЗНЕННЫЙ ЦИКЛ ЗОНЫ — то, что раньше было скриптами
  # zoneHolder и zoneInit прямо в этом файле: user namespace с двойным
  # маппингом, net+mount namespace, pasta, туннель, DNS и зеркало состояния
  # (`vpn-zone-core zone-holder`, rust/src/zone.rs). Заодно конфиги теперь
  # разбирает парсер крейта с тестами на все грабли docs/GOTCHAS.md §4, а не
  # конвейер sed+grep.
  #
  # Потом переехала ПЕСОЧНИЦА ФАЙЛОВОЙ СИСТЕМЫ — двухсотстрочный
  # writeShellScriptBin vpn-fs-sandbox из этого файла: bwrap, разрешения,
  # /.flatpak-info, фильтр сессионной шины и свой X-сервер
  # (`vpn-zone-core fs-sandbox`, rust/src/fs_sandbox.rs). Seccomp-фильтр она
  # теперь собирает В СВОЁМ ПРОЦЕССЕ (крейт зовётся как библиотека), а не
  # запускает vpn-zone-seccomp сабпроцессом.
  #
  # Затем переехал сам CLI `vpn-zone` — семьсот строк bash из части 3 этого
  # файла (rust/src/cli.rs + launch.rs + registry.rs).
  #
  # И последними — ПИКЕР СЕТИ и ВСЯ GUI-ОБВЯЗКА: четыреста строк vpn-zone-pick
  # и шесть writeShellScriptBin с диалогами (rust/src/picker.rs, rust/src/gui.rs
  # и общий rust/src/dialog.rs). Логики на shell в проекте не осталось нигде:
  # в этом файле от неё четыре двухстрочные обёртки, которые назначают
  # VPN_ZONE_TOOLS и делают exec.
  #
  # Пять бинарей: vpn-zone-seccomp (фильтр отдельной командой — он же selftest),
  # vpn-zone-core (подкоманды zone-holder, profile-run, sync, wl-sandbox и
  # fs-sandbox), vpn-zone (сам CLI), vpn-zone-pick (пикер) и vpn-zone-gui
  # (шесть ярлыков одной подкомандой каждый). ДВА ПЕРВЫХ ИМЕНЕМ СТАЛКИВАЮТСЯ с
  # обёртками из home.packages, поэтому крейт целиком туда не кладётся — в
  # профиль уходит symlink-набор vpn-zone-helpers (см. часть 3).
  # Сама деривация — в ../package.nix: её же собирает NixOS-модуль системного
  # уровня (module/nixos.nix, M10), и два одинаковых текста однажды разошлись
  # бы. Исходники и флаги прежние, поэтому и store-путь прежний.
  vpn-zone-rust = pkgs.callPackage ../package.nix { };
  # Окно запуска (сеть и контейнер рядом) — отдельный крейт с iced
  # (../window/package.nix): ядро выше от него не тяжелеет.
  vpn-zone-window = pkgs.callPackage ../window/package.nix { };

  # Чем открываются ссылки программ зоны и песочницы (LEAK-MODEL §2): xdg-open,
  # но без запасного браузера. Для схемы без обработчика xdg-open берёт
  # $BROWSER, а без него — первый нашедшийся из своего списка (firefox,
  # chromium, …) и запускает его САМ: мимо пикера, с основным профилем, в сети
  # той зоны, откуда пришла ссылка. `false` в BROWSER — отказ вместо этого;
  # ссылку со схемой, у которой есть обработчик (наш перехваченный ярлык),
  # это не трогает.
  #
  # И без портала: с NIXOS_XDG_OPEN_USE_PORTAL (xdg.portal.xdgOpenUsePortal)
  # xdg-open отдаёт ссылку OpenURI по сессионной шине — у обычной зоны это шина
  # хоста, и ссылка открывалась бы на хосте, мимо зоны (review 2026-09-25).
  vpn-zone-opener = pkgs.writeShellScript "vpn-zone-opener" ''
    export BROWSER=false
    unset NIXOS_XDG_OPEN_USE_PORTAL
    exec ${pkgs.xdg-utils}/bin/xdg-open "$@"
  '';

  # --- ЧАСТЬ 0б: ПЕСОЧНИЦА ФАЙЛОВОЙ СИСТЕМЫ — В RUST ---
  # Здесь был writeShellScriptBin vpn-fs-sandbox на две сотни строк. Он целиком
  # переехал в крейт — `vpn-zone-core fs-sandbox`, модуль rust/src/fs_sandbox.rs,
  # где и живёт теперь вся прежняя россыпь комментариев-граблей (порядок
  # аргументов bwrap, узлы NVIDIA, mimeapps.list, задержка X-сервера, отказ от
  # host-X11). Поведение прежнее; три отличия записаны в CHANGELOG.md:
  #   • seccomp-фильтр собирается В ЭТОМ ЖЕ ПРОЦЕССЕ (crate::seccomp как
  #     библиотека) и уходит в bwrap унаследованным дескриптором, вместо
  #     запуска vpn-zone-seccomp сабпроцессом и редиректа `exec 34< файл`;
  #   • не поднявшийся xdg-dbus-proxy больше не роняет запуск: bash биндил его
  #     сокет безусловно, bwrap падал на «Can't find source path», и программа
  #     не открывалась вовсе — вместо мягкой деградации получался отказ;
  #   • прокси гасится и когда сигнал приходит нам: в bash trap жил в сабшелле,
  #     который TERM убивал отдельно, оставляя прокси висеть.
  #
  # Коротко о том, зачем этот слой (подробности — в шапке rust/src/fs_sandbox.rs
  # и в docs/GOTCHAS.md §6, §8, §9). Третий слой поверх сети (зона) и данных
  # (контейнер): программа теряет доступ к $HOME целиком, вместо него tmpfs, а
  # наружу торчит только разрешённое. Всё остальное она просит через ПОРТАЛЫ —
  # и переключает её на них подложенный /.flatpak-info, по которому GTK, Qt,
  # Chromium и Electron решают, что изолированы. Полной заменой flatpak это не
  # является: программа берётся из nixpkgs и видит /nix/store, так что
  # «подменить библиотеку» песочница не мешает — она мешает читать ТВОИ файлы.
  #
  # Пути инструментов песочница получает флагами, как и держатель зоны: часть
  # кода исполняется внутри namespace, где PATH может быть каким угодно. Флаги
  # ей передаёт CLI, а сами пути лежат в манифесте ниже (bwrap, dbus-proxy,
  # kdialog, xwayland) — оттуда же их берёт смоук-тест, чтобы проверять ровно
  # то, что поедет пользователю (tests/integration/smoke.sh).

  # --- ЧАСТЬ 1-2: ЖИЗНЕННЫЙ ЦИКЛ ЗОНЫ — В RUST ---
  # Здесь были два shell-скрипта: zoneHolder (создавал user namespace двойным
  # маппингом и запускал pasta) и zoneInit (настраивал внутри туннель, маршруты
  # и DNS). Оба переехали в крейт целиком — `vpn-zone-core zone-holder <имя>`,
  # модуль rust/src/zone.rs. Держится всё на том же непривилегированном userns,
  # но namespace теперь ДВА: аплинк (там pasta и сокет туннеля) и зона
  # приложений, где нет ничего, кроме lo и awg0 — см. шапку файла и
  # docs/LEAK-MODEL.md.
  #
  # Что дал переезд:
  #   • конфиг разбирает оттестированный парсер (rust/src/config.rs) вместо
  #     конвейера sed+grep — CRLF, пустые I1…I5, три формы Endpoint и оба
  #     семейства адресов закрыты юнит-тестами (docs/GOTCHAS.md §4);
  #   • ни одной подстановки в shell: ip/awg/wg/pasta исполняются exec'ом
  #     напрямую, аргументами-массивами;
  #   • маппинг uid делается своим fork+newuidmap, а не через unshare(1).
  #
  # Контракт каталога зоны не изменился: zone.pid — это namespace ПРИЛОЖЕНИЙ
  # (цель nsenter в run/status), ready/status/resolv.conf — прежние. Добавился
  # uplink.pid; gc про него знать не обязан — он находит осиротевшую pasta по
  # номеру netns из её командной строки, а это теперь номер аплинка.
  # Пути инструментов подставляет Nix флагами в ExecStart юнита vpn-zone@ (см.
  # ниже): часть кода работает внутри namespace, где PATH может быть каким
  # угодно.

  # --- ЧАСТЬ 3: пользовательский CLI ---
  # Здесь лежали семьсот строк bash: add/up/down/list/status/check/run/gc,
  # реестр запусков с flock, разбор флагов запуска и вся остальная россыпь
  # команд. Всё переехало в крейт — `vpn-zone` (rust/src/cli.rs), запуск со
  # всеми граблями (rust/src/launch.rs) и реестр (rust/src/registry.rs).
  # Пользовательские тексты и коды выхода сохранены дословно: их читает человек
  # в терминале, а `cellward check` ещё и грепают.
  #
  # ПУТИ ИНСТРУМЕНТОВ — МАНИФЕСТОМ. Скомпилированный бинарь не умеет того, на
  # чём стоял скрипт: подстановки строк Nix'ом. А абсолютные пути обязательны —
  # часть кода работает внутри namespace, где PATH может быть каким угодно
  # (docs/GOTCHAS.md §12). Поэтому Nix кладёт их в маленький JSON в store, а
  # обёртка ниже показывает на него ЕДИНСТВЕННОЙ переменной окружения. Ключи
  # перечислены в rust/src/tools.rs; отсутствие любого — внятная ошибка при
  # старте, а не сюрприз посреди запуска программы.
  vpn-zone-tools = pkgs.writeText "vpn-zone-tools.json" (
    builtins.toJSON {
      home = config.home.homeDirectory;
      state = stateDir;
      profiles = profilesDir;
      sandboxes = "${config.home.homeDirectory}/.local/state/vpn-sandboxes";
      config = "${config.home.homeDirectory}/.config/vpn-zones";
      # ПРОФИЛЬНЫЕ пути, а не store: так разрывается зависимость по кругу
      # (cellward зовёт sync, sync подставляет cellward в ярлыки) и ярлыки не
      # протухают после каждой пересборки пакета (docs/GOTCHAS.md §10).
      # Главное имя, а не прежнее vpn-zone: ярлыки, которые пишет sync, и
      # запуски пикера не должны зависеть от псевдонима, который однажды уйдёт.
      runner = "${config.home.profileDirectory}/bin/cellward";
      picker = "${config.home.profileDirectory}/bin/vpn-zone-pick";
      # А ядро — наоборот, store-путём: оно версионируется вместе с CLI, и
      # разъезжаться им нельзя.
      core = "${vpn-zone-rust}/bin/vpn-zone-core";
      systemctl = "${pkgs.systemd}/bin/systemctl";
      systemd-run = "${pkgs.systemd}/bin/systemd-run";
      nsenter = "${pkgs.util-linux}/bin/nsenter";
      unshare = "${pkgs.util-linux}/bin/unshare";
      ip = iproute;
      inherit kdialog;
      # Уведомления шлёт только vpn-zone-gui: у CLI то же самое печатается в
      # stdout, а у пикера уведомлению взяться неоткуда — он становится
      # программой.
      notify-send = notify;
      # Эти три CLI не запускает сам — он передаёт их флагами песочнице ФС,
      # ровно как юнит передаёт держателю зоны --ip/--pasta.
      bwrap = "${pkgs.bubblewrap}/bin/bwrap";
      dbus-proxy = "${dbusProxy}/bin/xdg-dbus-proxy";
      xwayland = "${pkgs.xwayland-satellite}/bin/xwayland-satellite";
      # Доверенные сертификаты контейнеров (docs/CERTIFICATES.ru.md): openssl
      # разбирает сертификат при `cellward trust add`, certutil ставит его в
      # базы NSS контейнера из `profile-run`.
      openssl = "${pkgs.openssl}/bin/openssl";
      certutil = "${pkgs.nss.tools}/bin/certutil";
      # Ссылки программ из песочницы на хосте, когда брокера нет (LEAK-MODEL §2):
      # портал им отвечает фильтр шины песочницы, открывает xdg-open. Из зоны
      # ссылки идут брокеру (PERMISSIONS §11.13).
      opener = "${vpn-zone-opener}";
      # Окно запуска: пикер спрашивает им вместо двух меню kdialog.
      window = "${vpn-zone-window}/bin/vpn-zone-window";
      # Выбор программы для ссылки из зоны: окно бэкенда портала
      # (AppChooser), зовёт брокер (rust/src/links.rs).
      busctl = "${pkgs.systemd}/bin/busctl";
      # awg/wg/pasta/nft/openconnect здесь намеренно НЕТ: их зовёт только
      # держатель зоны, и получает он их флагами ExecStart своего юнита.
      # Дублировать пути в двух местах — значит однажды поменять их в одном.
    }
  );

  # Команда с псевдонимами: скрипт в две строки — назначить манифест и стать
  # бинарём крейта, — и ссылки на него под другими именами в том же пакете.
  withAliases =
    name: aliases: binary:
    pkgs.runCommand name { } (
      ''
        install -Dm755 ${pkgs.writeShellScript name ''
          export VPN_ZONE_TOOLS=${vpn-zone-tools}
          exec ${vpn-zone-rust}/bin/${binary} "$@"
        ''} $out/bin/${name}
      ''
      + lib.concatMapStrings (alias: ''
        ln -s ${name} $out/bin/${alias}
      '') aliases
    );

  # Главная команда — cellward, cw — её короткое имя, vpn-zone — прежнее, на
  # время перехода: один и тот же скрипт. По имени cellward CLI зовут пикер,
  # GUI и ярлыки (runner в манифесте). Бинарь в крейте по-прежнему
  # bin/vpn-zone, поэтому крейт целиком в профиль не кладётся (см.
  # vpn-zone-helpers ниже), иначе два одинаковых имени столкнулись бы.
  cellward = withAliases "cellward" [
    "cw"
    "vpn-zone"
  ] "vpn-zone";

  # Помощники крейта в PATH: ядро (его зовёт юнит vpn-zone@ и сам CLI) и
  # генератор seccomp-фильтра — тем же бинарём проверяется, что фильтр вообще
  # работает на твоём ядре (`vpn-zone-seccomp selftest`). Симлинки, а не копии:
  # ссылка на store-путь тянет за собой сам крейт.
  vpn-zone-helpers = pkgs.runCommand "vpn-zone-helpers" { } ''
    mkdir -p $out/bin
    ln -s ${vpn-zone-rust}/bin/vpn-zone-core $out/bin/vpn-zone-core
    ln -s ${vpn-zone-rust}/bin/vpn-zone-seccomp $out/bin/vpn-zone-seccomp
  '';

  # Tab-дополнение для zsh и bash — тонкие обёртки над скрытой подкомандой
  # `cellward _complete` (rust/src/completion.rs): правила и знание зон,
  # профилей и песочниц живут в крейте рядом с самими командами и покрыты
  # тестами, оболочка только спрашивает и подставляет. Протокол: слова
  # командной строки + 1-based позиция курсора, кандидаты по одному на строку;
  # специальный ответ __files__ — «дополняй файлами сам». NixOS кладёт
  # site-functions профилей в fpath через NIX_PROFILES (/etc/zshrc), bash
  # подхватывает completions профиля пакетом bash-completion. Одно дополнение
  # на все три имени команды: zsh берёт их из #compdef, а bash-completion ищет
  # файл по имени набранной команды — отсюда ссылки cw и vpn-zone на cellward.
  cellward-completions =
    let
      zshScript = pkgs.writeText "cellward.zsh-completion" ''
        #compdef cellward cw vpn-zone
        local -a candidates
        candidates=("''${(@f)$(cellward _complete -- "''${(@)words}" "$CURRENT" 2>/dev/null)}")
        if [[ "''${candidates[1]-}" == __files__ ]]; then
          _files
          return
        fi
        [[ -n "''${candidates[1]-}" ]] && compadd -- "''${candidates[@]}"
      '';
      bashScript = pkgs.writeText "cellward.bash-completion" ''
        _cellward() {
          local -a reply
          mapfile -t reply < <(cellward _complete -- "''${COMP_WORDS[@]}" "$((COMP_CWORD + 1))" 2>/dev/null)
          if [[ "''${reply[0]-}" == __files__ ]]; then
            compopt -o default
            COMPREPLY=()
            return
          fi
          COMPREPLY=("''${reply[@]}")
        }
        complete -F _cellward cellward cw vpn-zone
      '';
    in
    pkgs.runCommand "cellward-completions" { } ''
      install -Dm444 ${zshScript} $out/share/zsh/site-functions/_cellward
      install -Dm444 ${bashScript} $out/share/bash-completion/completions/cellward
      ln -s cellward $out/share/bash-completion/completions/cw
      ln -s cellward $out/share/bash-completion/completions/vpn-zone
    '';

  # --- ЧАСТЬ 3б: ПИКЕР СЕТИ ---
  # Спрашивает при запуске, куда пустить программу. Вызывается из перехваченных
  # ярлыков (режим picker).
  #
  # Здесь лежали четыреста строк bash: три уровня памяти, два меню kdialog,
  # закрепления по двум независимым осям и re-exec самого себя для второго
  # прохода. Всё переехало в крейт целиком (`vpn-zone-pick`,
  # rust/src/picker.rs), причём решение «какая сеть и какой контейнер» стало
  # ЧИСТОЙ ФУНКЦИЕЙ от снимка состояния — у каждой ветки теперь есть тест, а не
  # только история багфикса. Тексты диалогов, имена файлов памяти и порядок
  # пунктов меню сохранены дословно.
  #
  # ТРИ УРОВНЯ ПАМЯТИ, от сильного к слабому:
  #   1. ЗАКРЕПЛЕНИЕ (.pinned/<программа>) — диалога нет вообще, программа сразу
  #      уходит в назначенную сеть. Ставится пунктом «Всегда: …» прямо в меню,
  #      снимается пунктом «Спрашивать снова», ярлыком «Сбросить сети программ»
  #      или командой `cellward forget`.
  #   2. ПОСЛЕДНИЙ ВЫБОР (.last/<программа>) — диалог показывается, но нужный
  #      пункт уже выделен.
  #   3. ОБЩИЙ ДЕФОЛТ (~/.config/vpn-zones/default), по умолчанию «offline».
  #      Это и есть политика «незнакомая программа в интернет не идёт»: пока ты
  #      явно не выбрал сеть, предлагается вариант без неё.
  #
  # Сеть и контейнер закрепляются ПОРОЗНЬ (.pinned и .pinnedprofile): это
  # независимые оси, и диалог показывается только для незакреплённой.
  # Принудительно вызвать диалог при закреплённой программе: VPN_ZONE_ASK=1.
  # VPN_ZONE_PROFILE — служебная: ею пикер передаёт САМ СЕБЕ выбранный
  # контейнер между двумя проходами («⚙ Сменить контейнер» → снова вопрос о
  # сети). Руками её ставить незачем, и она снимается сразу после чтения.
  #
  # Обёртка двухстрочная, как у cellward, и по той же причине: имя
  # vpn-zone-pick В ПРОФИЛЕ занимает именно она, потому что этот путь попадает в
  # Exec сгенерированных ярлыков и не должен протухать при каждой пересборке
  # пакета (docs/GOTCHAS.md §10).
  vpn-zone-pick = pkgs.writeShellScriptBin "vpn-zone-pick" ''
    export VPN_ZONE_TOOLS=${vpn-zone-tools}
    exec ${vpn-zone-rust}/bin/vpn-zone-pick "$@"
  '';

  # --- ЧАСТЬ 4: генерация ярлыков ---
  # Разбором занимается крейт rust/ (модуль desktop), а не sed: .desktop — это
  # ini с локализованными ключами и экранированием, и разбирать его построчно
  # значит однажды получить ярлык с поехавшим Exec. Здесь остаётся тонкая
  # обёртка, которая подставляет четыре пути.
  # Третий аргумент — путь к cellward, который попадёт в Exec ярлыков. Берём
  # ПРОФИЛЬНЫЙ путь, а не store: во-первых, это разрывает зависимость по кругу
  # (cellward зовёт sync, sync подставляет cellward), во-вторых, ярлыки не
  # протухают при каждом обновлении пакета — иначе после любой пересборки они
  # указывали бы на старый store-путь до следующего sync.
  vpn-zone-sync = pkgs.writeShellScriptBin "vpn-zone-sync" ''
    exec ${vpn-zone-rust}/bin/vpn-zone-core sync \
      "${stateDir}" "${config.home.homeDirectory}" \
      "${config.home.profileDirectory}/bin/cellward" \
      "${config.home.profileDirectory}/bin/vpn-zone-pick" \
      "${pkgs.systemd}/bin/systemctl"
  '';

  # --- ЧАСТЬ 4б: ГРАФИЧЕСКИЕ ЯРЛЫКИ ---
  # Здесь лежали шесть writeShellScriptBin — добавить зону, удалить зону,
  # завести контейнер, удалить контейнер, настройки и сброс закреплений. Все
  # шесть были kdialog поверх CLI, и все шесть переехали в крейт одной
  # подкомандой каждый (`vpn-zone-gui <команда>`, rust/src/gui.rs). Тексты
  # диалогов и уведомлений сохранены дословно — включая те места, где bash
  # передавал kdialog литеральные «\n» (в Nix-строке '' … '' обратный слэш
  # ничего не экранирует, и эти два символа так и доезжали до диалога).
  #
  # Ярлыкам обёртка не нужна: их пишет сам home-manager и пересобирает на
  # каждом switch, так что store-путь в них не протухает. (У Exec, который
  # генерирует НАШ sync, путь наоборот профильный — там между пересборками никто
  # ярлыки не переписывает, docs/GOTCHAS.md §10.) Манифест ярлык несёт сам,
  # через env(1) абсолютным путём:
  #   Exec=env VPN_ZONE_TOOLS=… …/vpn-zone-gui add
  guiExec =
    verb:
    "${pkgs.coreutils}/bin/env VPN_ZONE_TOOLS=${vpn-zone-tools} ${vpn-zone-rust}/bin/vpn-zone-gui ${verb}";

  # А в PATH окна кладёт двухстрочная обёртка, как у cellward: их открывают и
  # не из ярлыков — конфигуратор (nix_cm зовёт `vpn-zone-gui containers`),
  # человек из терминала. Без неё такой запуск падал с ENOENT: бинарь был
  # только в store-пути ярлыков. cellward-gui — главное имя, vpn-zone-gui —
  # прежнее, на время перехода.
  cellward-gui = withAliases "cellward-gui" [ "vpn-zone-gui" ] "vpn-zone-gui";

  # --- ЧАСТЬ 5: ДЕКЛАРАТИВНАЯ СТОРОНА (docs/CONTAINERS.ru.md §8) ---
  # Опции ниже — единственный интерфейс для конфигураторов (nix_cm и подобных):
  # они ставят опции, а модуль пишет файлы в ~/.config/vpn-zones/declared/.
  # Рантайм читает их первыми (Nix сильнее локального) и отказывается менять из
  # CLI/GUI то, что задано здесь, — вместо того чтобы молча не сработать.
  # Машиночитаемый ответ, откуда какое значение, — `cellward status --json`.
  cfg = config.programs.cellward;
  # A term as `cellward ask-again` takes it (`30s`, `3m`, `1h`, `1d`) in
  # seconds; bounds as in rust/src/grants.rs (ASK_AGAIN_MIN, ASK_AGAIN_MAX).
  termSeconds =
    t:
    let
      m = builtins.match "([1-9][0-9]{0,5})([smhd])" t;
    in
    lib.toInt (builtins.elemAt m 0)
    * {
      s = 1;
      m = 60;
      h = 3600;
      d = 86400;
    }.${builtins.elemAt m 1};
  askAgainTerm = lib.types.addCheck (lib.types.strMatching "[1-9][0-9]{0,5}[smhd]") (
    t: termSeconds t >= 30 && termSeconds t <= 86400
  );
  # The waits that end by a clock on purpose (rust/src/timings.rs): the same
  # bounds as there.
  questionTerm = lib.types.addCheck (lib.types.strMatching "never|[1-9][0-9]{0,5}[smhd]") (
    t: t == "never" || (termSeconds t >= 30 && termSeconds t <= 86400)
  );
  handshakeTerm = lib.types.addCheck (lib.types.strMatching "[1-9][0-9]{0,5}[smhd]") (
    t: termSeconds t >= 1 && termSeconds t <= 600
  );

  # Имя контейнера попадает в путь, в имя файла и в имя деривации.
  # Не `__…` и не слова, которые меню используют как свои метки: контейнер с
  # таким именем рантайм не прочитал бы (`__main__`, `__fs__`) или принял бы за
  # команду (`main`, `own`, `ask`, `pinmain`) — и объявленная привязка к сети
  # молча не действовала бы (review 2026-09-25).
  validName =
    name:
    builtins.match "[A-Za-z0-9_][A-Za-z0-9_.-]*" name != null
    && !(lib.hasPrefix "__" name)
    && !(lib.elem name [
      "main"
      "own"
      "ask"
      "pinmain"
      "unpinprof"
    ]);

  # Доверенные корневые сертификаты контейнера (docs/CERTIFICATES.ru.md),
  # приведённые к виду, который читает рантайм: `<sha256>.pem` на сертификат.
  # Проверки — ПРИ СБОРКЕ, а не при запуске: файл с несколькими сертификатами
  # (бандл протащил бы все свои корни) и сертификат не УЦ (лист корнем быть не
  # может) ломают сборку конфигурации, а не молча доезжают до контейнера.
  trustDir =
    name: certs:
    pkgs.runCommand "vpn-zones-trust-${name}" { nativeBuildInputs = [ pkgs.openssl ]; } (
      ''
        mkdir -p "$out"
      ''
      + lib.concatMapStrings (cert: ''
        n=$(grep -c 'BEGIN CERTIFICATE' ${cert} || true)
        if [ "$n" -gt 1 ]; then
          echo "${cert}: сертификатов в файле: $n — по одному на файл" >&2
          exit 1
        fi
        if [ "$n" = 1 ]; then form=PEM; else form=DER; fi
        if ! openssl x509 -inform "$form" -in ${cert} -noout -ext basicConstraints | grep -q 'CA:TRUE'; then
          echo "${cert}: не сертификат удостоверяющего центра (нет basicConstraints CA:TRUE)" >&2
          exit 1
        fi
        fp=$(openssl x509 -inform "$form" -in ${cert} -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')
        openssl x509 -inform "$form" -in ${cert} -outform PEM > "$out/$fp.pem"
      '') certs
    );

  renderContainer =
    name: c:
    lib.concatStringsSep "\n" (
      [
        "# Объявлено в Nix: programs.cellward.containers.${name}. Меняется там, не здесь."
        # Вид дома — всегда: по строке home рантайм отличает этот файл от
        # файлов прежнего вида (<вид>-<имя>.conf).
        "home = ${homeKind c.home}"
      ]
      ++ lib.optional (c.network != null) "network = ${c.network}"
      ++ map (app: "app = ${app}") c.apps
      ++ lib.optional (c.trust.certificates != [ ]) "trust = ${trustDir name c.trust.certificates}"
      ++ map (path: "path = ${path}") c.permissions.paths
      # Its own word both ways (2026-09-28): false refuses its zone's X
      # server (zoneX11) too; null, none of its own — the zone's.
      ++ lib.optional (c.permissions.x11 != null) "x11 = ${lib.boolToString c.permissions.x11}"
      ++ lib.optional (c.frameColor != null) "frame_color = ${c.frameColor}"
      ++ lib.optional (c.permissions.microphone != null) "microphone = ${c.permissions.microphone}"
      ++ lib.optional (c.permissions.screencast != null) "screencast = ${c.permissions.screencast}"
      ++ lib.optional (c.permissions.camera != null) "camera = ${lib.boolToString c.permissions.camera}"
      # A container's own zone-level permissions (stage 5 of the container
      # design, rust/src/hermetic.rs CONTAINER_KEYS): only where set.
      ++ lib.optional (
        c.permissions.hermetic != null
      ) "hermetic = ${lib.boolToString c.permissions.hermetic}"
      ++ lib.optional (
        c.permissions.nixDaemon != null
      ) "nix_daemon = ${lib.boolToString c.permissions.nixDaemon}"
      ++ lib.optional (
        c.permissions.hostFilesWritable != null
      ) "host_files_writable = ${lib.boolToString c.permissions.hostFilesWritable}"
      ++ lib.optional (
        c.permissions.audioManager != null
      ) "audio_manager = ${lib.boolToString c.permissions.audioManager}"
      ++ lib.optional (c.focus != null) "focus = ${c.focus}"
      ++ map (device: "device = ${device}") c.permissions.devices
      ++ lib.mapAttrsToList (scheme: app: "link = ${scheme} ${app}") c.links
    )
    + "\n";

  # overlay — прежнее слово для layer.
  homeKind = home: if home == "overlay" then "layer" else home;

  # A path of programs.cellward.protect, one below or above one: what a
  # container of the real home may be given to write (rust/src/protect.rs).
  inProtect =
    v: lib.any (p: v == p || lib.hasPrefix "${p}/" v || lib.hasPrefix "${v}/" p) cfg.protect;

  allApps = lib.concatMap (c: c.apps) (lib.attrValues cfg.containers);
  duplicateApps = lib.filter (app: lib.count (x: x == app) allApps > 1) (lib.unique allApps);

  containerModule = {
    options = {
      home = lib.mkOption {
        type = lib.types.enum [
          "private"
          "layer"
          "overlay"
          "main"
        ];
        default = "private";
        description = "Дом контейнера: private — свой пустой дом; layer — слой над всем настоящим домом: видно всё, пишется в слой контейнера (overlay — прежнее слово для него); main — сам настоящий дом, без разделения данных, но со своими сетью, программами и разрешениями (файловый менеджер, свой терминал). Смена вида дома не создаёт другого контейнера: данные прежнего вида откладываются рядом.";
      };
      network = lib.mkOption {
        # Имя зоны (латиница, цифры, _ и -, не с дефиса), ask, offline,
        # unconfined или direct: что-то другое не привязало бы ни к чему —
        # CLI молча брал бы локальное значение (review 2026-09-24).
        type = lib.types.nullOr (lib.types.strMatching "[A-Za-z0-9_][A-Za-z0-9_-]*");
        default = null;
        example = "offline";
        description = "Сеть контейнера: имя зоны, unconfined (без ограничений: сеть хоста, без VPN и без изоляции зоны; прежнее имя direct тоже принимается) или offline. Запуск в другой сети — отказ. null — сеть не задана в Nix и меняется локально (`cellward container set`).";
      };
      apps = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "firefox" ];
        description = "Программы (id ярлыков, имя .desktop без расширения), которые запускаются в этом контейнере без вопроса.";
      };
      frameColor = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "#[0-9a-fA-F]{6}");
        default = null;
        example = "#d94c4c";
        description = "Цвет рамки окон программ контейнера (#rrggbb). null — цвет его сети (programs.cellward.frame.colors), а у неё — из имени.";
      };
      focus = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.enum [
            "input"
            "notify"
            "ask"
            "allow"
          ]
        );
        default = null;
        example = "notify";
        description = "Может ли программа контейнера забрать фокус клавиатуры (xdg-activation: просьба активировать окно; посредник Wayland видит каждую такую просьбу): input — один раз на щелчок или клавишу человека (первая просьба с серийным номером этого события проходит, повторные — нет), notify — ни одна не проходит, вместо неё уведомление «<программа> просит внимания» с кнопкой «Перейти», ask — вопрос «Переключить фокус на <программа>?», allow — все проходят, как без посредника. null — input или как задано локально (cellward container set <контейнер> focus). Фокус нового окна при открытии решает композитор (у niri — правило окна open-focused). Действует для программ, запущенных после изменения.";
      };
      permissions.x11 = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        example = false;
        description = "Свой X-сервер (xwayland-satellite) для программ контейнера в зонах: true — есть, false — нет, даже если его даёт сеть (programs.cellward.zoneX11, cellward x11 <зона>), null — как у сети или как задано локально (cellward container set <контейнер> x11 default|on|off). До 2026-09-28 false значило «своего нет» и X-сервер сети всё равно был. X-сервер хоста из зон недоступен всегда: он показывает каждому клиенту окна, ввод и буфер обмена всех остальных. Действует для программ, запущенных после изменения. См. docs/HERMETICITY.ru.md §7.";
      };
      permissions.microphone = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.enum [
            "yes"
            "no"
            "ask"
          ]
        );
        default = null;
        example = "ask";
        description = "Может ли программа контейнера записывать микрофон: yes (без вопроса), no (никогда) или ask — спросить при первой записи: один раз, всегда (этому контейнеру) или отказать. Контейнер знают по запуску, из которого вышла программа (docs/PERMISSIONS.md §11.10). null — как у его зоны (programs.cellward.microphone) или как задано локально (cellward container set <контейнер> microphone). Значение зоны из Nix важнее местной настройки контейнера, если та шире; строже — действует (местное «нет» при «да» зоны из Nix — «нет»); значение контейнера из Nix — важнее всего. Путь PulseAudio; ограниченный PipeWire герметичной зоны пока решает по зоне.";
      };
      links = lib.mkOption {
        type = lib.types.attrsOf (lib.types.strMatching "[^[:space:]/]+");
        default = { };
        example = {
          https = "firefox";
          tg = "org.telegram.desktop";
        };
        description = "В какой программе открывать ссылки схемы из этого контейнера без выбора программы (docs/PERMISSIONS.md §11.13): схема → id ярлыка (имя .desktop-файла без расширения). Окно сети и контейнера при этом остаётся. Без правила программу для ссылки предлагает окно выбора дистрибутива (портал); системное умолчание (mimeapps.list) cellward не меняет. Локально — cellward container links.";
      };
      permissions.devices = lib.mkOption {
        type = lib.types.listOf (
          lib.types.strMatching "games|security-keys|phone|serial|vm|usb:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}(:[!-9;<>-~]{1,128})?"
        );
        default = [ ];
        example = [
          "security-keys"
          "usb:1050:0407"
        ];
        description = "Устройства, которые зоны закрывают всем своим программам и которые выдаются этому контейнеру (docs/PERMISSIONS.md §11.12): наборы games (геймпады и их HID), security-keys (ключи FIDO), phone (adb, MTP), serial (ttyUSB, ttyACM), vm (kvm, vhost-net, vhost-vsock, net/tun — виртуальные машины) или одно устройство usb:<производитель>:<модель>[:<серийный>] — все его узлы; что подключено — cellward devices. Действует для программ, запущенных после изменения; устройство, подключённое позже, видно после перезапуска программы.";
      };
      permissions.camera = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        example = true;
        description = "Видны ли программам контейнера камеры хоста (/dev/video*, /dev/media*): зона закрывает их всем своим программам, а запуск, которому они разрешены, открывает их в своём пространстве монтирования. null — как у его зоны (programs.cellward.camera) или как задано локально (cellward container set <контейнер> camera). Значение зоны из Nix важнее местной настройки контейнера, если та шире; строже — действует (местное «нет» при «да» зоны из Nix — «нет»); значение контейнера из Nix — важнее всего. Действует для программ, запущенных после изменения; камера, подключённая позже, закрыта у всех — перезапустите программу.";
      };
      permissions.hermetic = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        example = false;
        description = "Герметичен ли контейнер: без systemd --user, сессионная шина через фильтр, запуск в других сетях — только через брокер с вопросом, свои /tmp. null — как у его сети (programs.cellward.hermetic.default, hermetic.exceptions или cellward hermetic <зона>) или как задано локально (cellward container set <контейнер> hermetic); значение контейнера из Nix важнее местного. Без герметичности контейнер только там, где сеть это допускает (она сама не герметична); offline и запертая зона (cellward lock) не допускают никогда — там он герметичен, что бы ни было задано (cellward explain <контейнер>). Действует со следующего подъёма экземпляра контейнера (cellward status: restart_needed). См. docs/HERMETICITY.ru.md §7.";
      };
      permissions.nixDaemon = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        example = true;
        description = "Виден ли программам контейнера Nix-демон хоста (nix-shell, nix build). По умолчанию нет: демон качает и собирает в сети хоста, мимо VPN, и производная с фиксированным хешем скачает любой адрес, который назовёт программа. null — как у его сети (programs.cellward.nixDaemon) или как задано локально (cellward container set <контейнер> nix-daemon); значение контейнера из Nix важнее местного. Виден только в сетях, которые его допускают (programs.cellward.nixDaemon, cellward nix-daemon <зона> on); offline — никогда. Контейнеру со своим домом (home = \"private\") не виден вовсе. Действует со следующего подъёма экземпляра контейнера.";
      };
      permissions.hostFilesWritable = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        example = true;
        description = "Может ли герметичный контейнер писать туда, что хост исполняет из дома: автозапуск, юниты, ярлыки, конфиги оболочек и композитора, ~/.ssh. По умолчанию только для чтения. null — как у его сети (programs.cellward.hostFilesWritable) или как задано локально (cellward container set <контейнер> host-files); значение контейнера из Nix важнее местного. Только в сетях, которые это допускают (programs.cellward.hostFilesWritable, cellward host-files <зона> writable); offline — никогда. Действует со следующего подъёма экземпляра контейнера.";
      };
      permissions.audioManager = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        example = true;
        description = "Отдаётся ли герметичному контейнеру pipewire-0 хоста как есть — для микшера или коммутатора (pavucontrol, qpwgraph). По умолчанию нет: такой контейнер слышит всё, что играет хост, записывает микрофон мимо microphone и меняет чужие потоки. null — как у его сети (programs.cellward.audioManager, устарело) или как задано локально (cellward container set <контейнер> audio-manager). Порядок — как у permissions.hermetic. Действует со следующего подъёма экземпляра контейнера.";
      };
      permissions.screencast = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.enum [
            "yes"
            "no"
            "ask"
          ]
        );
        default = null;
        example = "no";
        description = "Может ли программа контейнера транслировать экран через портал: no — отказ на каждый вызов, ask — диалог портала каждый раз, yes — выбор можно запомнить: портал знает программы контейнера по его собственному имени cellward.c.<контейнер> (ярлык для портала кладёт sync), и запомненное — контейнера, а не всей зоны. Контейнер знают по запуску, из которого вышла программа (docs/PERMISSIONS.md §11.10). null — как у его зоны (programs.cellward.screencast) или как задано локально (cellward container set <контейнер> screencast). Значение зоны из Nix важнее местной настройки контейнера, если та шире; строже — действует (местное «нет» при «да» зоны из Nix — «нет»); значение контейнера из Nix — важнее всего. Держит фильтр шины герметичной зоны.";
      };
      permissions.paths = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "~/.wine"
          "/mnt/games/SteamLibrary"
        ];
        description = "Пути настоящего дома (~/…) или дисков (/mnt, /media, /run/media, /srv), которые программы контейнера меняют в настоящем: своему дому (home = \"private\") они видны только так, слою над домом (home = \"overlay\") — видны и так, но пишутся мимо слоя, в настоящий дом (только ~/…). Состояние cellward, весь дом, места, откуда хост что-то запускает (автозапуск, .bashrc, ~/.local/bin…), и остальные места (/run, /tmp, /etc…) не выдаются; такой путь пропускается при запуске с предупреждением. То, что программы положат сюда, видно вне контейнера.";
      };
      trust = {
        certificates = lib.mkOption {
          # Проверка ключа — в типе, до того как файл скопирован в store: файл
          # с ключом УЦ (mitmproxy кладёт ключ и сертификат вместе) целиком
          # оказался бы в /nix/store, открытым для чтения всем, и любой мог бы
          # подписать сертификат, которому контейнер верит (review 2026-09-25).
          type = lib.types.listOf (
            lib.types.addCheck lib.types.path (p: !(lib.hasInfix "PRIVATE KEY" (builtins.readFile p)))
            // {
              description = "path to a certificate without a private key";
            }
          );
          default = [ ];
          description = "Дополнительные корневые сертификаты (PEM или DER, по одному в файле), которым доверяют ТОЛЬКО программы этого контейнера. Владелец ключа такого сертификата читает и подменяет их TLS-трафик. См. docs/CERTIFICATES.ru.md.";
        };
        acknowledgeRisk = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Обязательное подтверждение для непустого certificates: программы контейнера будут доверять этим корням.";
        };
      };
    };
  };

  # Every option of programs.cellward, by its path below it: each one is renamed
  # on its own, not the subtree — a renamed subtree is one option of an empty
  # submodule type and would refuse every definition under it.
  # tests/harness.nix checks that this list names every option.
  renamedOptions = [
    "enable"
    "defaults.network"
    "defaults.container"
    "defaults.permissions.microphone"
    "defaults.permissions.screencast"
    "launcher.mode"
    "interception.userEntries"
    "autostart.unassigned"
    "zoneX11"
    "nixDaemon"
    "camera"
    "audioManager"
    "pipewirePolicy"
    "hostFilesWritable"
    "microphone"
    "screencast"
    "askAgainAfter"
    "questionTimeout"
    "netlog.keepDays"
    "netlog.maxSize"
    "protect"
    "handshakeCheckAfter"
    "hermetic.default"
    "hermetic.exceptions"
    "pathShims.enable"
    "tunnelWatch.enable"
    "waylandProxy.enable"
    "waylandProxy.exceptions"
    "frame.colors"
    "frame.width"
    "frame.title"
    "frame.style"
    "frame.buttons"
    "frame.radius"
    "tray.badge"
    "compositorRestriction.enable"
    "desktop.windowMenu.key"
    "desktop.floatWindows"
    "desktop.niri.enable"
    "desktop.niri.includeInConfig"
    "desktop.sway.enable"
    "containers"
    "main"
  ];

  # --- desktop: the window menu's key and our windows' rule ----------------
  menuKey = cfg.desktop.windowMenu.key;
  menuCommand = "${cellward}/bin/cellward";
  keyParts = lib.splitString "+" menuKey;
  # sway: Mod4 is the logo key (niri's Mod on a TTY), Mod1 Alt; a letter is its
  # lower-case keysym, as sway's own examples write it.
  swayModifier =
    m:
    {
      Mod = "Mod4";
      Super = "Mod4";
      Ctrl = "Control";
      Control = "Control";
      Alt = "Mod1";
      Shift = "Shift";
    }
    .${m};
  swayKey =
    let
      key = lib.last keyParts;
    in
    lib.concatStringsSep "+" (
      map swayModifier (lib.init keyParts)
      ++ [ (if builtins.stringLength key == 1 then lib.toLower key else key) ]
    );
  niriSnippet = ''
    // cellward: programs.cellward.desktop — written by home-manager.
  ''
  + lib.optionalString (menuKey != null) ''
    binds {
        ${menuKey} hotkey-overlay-title="Сеть и контейнер окна (cellward)" { spawn "${menuCommand}" "window-menu"; }
    }
  ''
  + lib.optionalString cfg.desktop.floatWindows ''
    window-rule {
        match app-id="^vpn-zone-window$"
        open-floating true
    }
  '';
  swaySnippet = ''
    # cellward: programs.cellward.desktop — written by home-manager.
    # The focus notice of a zone's program focuses its window through
    # sway's IPC, from a unit of systemd --user: the manager needs SWAYSOCK
    # (niri gives it NIRI_SOCKET itself).
    exec ${pkgs.systemd}/bin/systemctl --user import-environment SWAYSOCK
  ''
  + lib.optionalString (menuKey != null) ''
    bindsym ${swayKey} exec ${menuCommand} window-menu
  ''
  + lib.optionalString cfg.desktop.floatWindows ''
    for_window [app_id="^vpn-zone-window$"] floating enable
  '';
in
{
  # The project was vpn-zones until 2026-09: every option of programs.cellward
  # also answers to its old name under programs.vpn-zones, with a warning.
  imports = map (
    name:
    lib.mkRenamedOptionModule (lib.splitString "." "programs.vpn-zones.${name}") (
      lib.splitString "." "programs.cellward.${name}"
    )
  ) renamedOptions;

  options.programs.cellward = {
    enable = lib.mkEnableOption "cellward: сетевые зоны с VPN и контейнеры для запуска программ";

    defaults = {
      network = lib.mkOption {
        # Имя зоны (латиница, цифры, _ и -, не с дефиса), ask, offline,
        # unconfined или direct: что-то другое не привязало бы ни к чему —
        # CLI молча брал бы локальное значение (review 2026-09-24).
        type = lib.types.nullOr (lib.types.strMatching "[A-Za-z0-9_][A-Za-z0-9_-]*");
        default = null;
        example = "offline";
        description = "Сеть, которую пикер предлагает незнакомой программе: offline, unconfined (без ограничений: сеть хоста, без VPN и без изоляции зоны; прежнее имя direct тоже принимается) или имя зоны. null — не задавать из Nix (`cellward default`).";
      };
      container = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.addCheck lib.types.str (
            v:
            lib.elem v [
              "ask"
              "main"
              "own"
            ]
            || validName (lib.removePrefix "sb:" v)
          )
        );
        default = null;
        example = "own";
        description = "Контейнер для запусков по умолчанию: ask, main, own (свой дом у каждой программы) или имя контейнера. null — не задавать из Nix.";
      };
      permissions = {
        microphone = lib.mkOption {
          type = lib.types.nullOr (lib.types.enum [ "yes" "no" "ask" ]);
          default = null;
          example = "ask";
          description = "Не действует с 2026-09-29: сеть больше не решает это за свои программы (docs/PERMISSIONS.md §11.15) — defaults.permissions.microphone, containers.<имя>.permissions.microphone, main.permissions.microphone. Прочитано один раз, при переносе в контейнеры: контейнер, привязанный к сети, получил её значение своим. Прежнее описание: Микрофон программ контейнера без своего слова (и настоящего дома без своего): yes, no или ask — спросить при первой записи. Сеть этого больше не решает (docs/PERMISSIONS.md §11.15). Своё слово контейнера — containers.<имя>.permissions.microphone, настоящего дома — main.permissions.microphone; оно берёт верх над этим в обе стороны. null — не задавать из Nix (cellward defaults set microphone …, иначе ask).";
        };
        screencast = lib.mkOption {
          type = lib.types.nullOr (lib.types.enum [ "yes" "no" "ask" ]);
          default = null;
          example = "ask";
          description = "Не действует с 2026-09-29: сеть больше не решает это за свои программы (docs/PERMISSIONS.md §11.15) — defaults.permissions.screencast, containers.<имя>.permissions.screencast, main.permissions.screencast. Прочитано один раз, при переносе в контейнеры: контейнер, привязанный к сети, получил её значение своим. Прежнее описание: Трансляция экрана через портал у программ контейнера без своего слова: yes, no или ask. Как microphone выше. null — не задавать из Nix (cellward defaults set screencast …, иначе ask).";
        };
      };
    };

    launcher.mode = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "picker"
          "per-zone"
          "both"
          "off"
        ]
      );
      default = null;
      description = "Как генерируются ярлыки (per-zone и both устарели). null — не задавать из Nix.";
    };

    interception.userEntries = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "take-over"
          "leave"
        ]
      );
      default = null;
      description = "Чужие записи в ~/.local/share/applications (игры Steam, userapp-* программ, ставших обработчиками по умолчанию, веб-приложения, Wine): take-over — перехватывать на месте, сохраняя оригинал (по умолчанию), leave — не трогать. null — не задавать из Nix. См. docs/LAUNCHERS.ru.md §3.2.";
    };

    autostart.unassigned = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "ask"
          "offline"
          "as-is"
        ]
      );
      default = null;
      description = "Записи ~/.config/autostart (обычные файлы; symlink не трогаются) перехватываются на месте: при входе программа без диалога стартует туда, что для неё выбрано (закрепление, назначенный контейнер и его сеть). Невыбранное: ask — пикер при входе, с «всегда» (по умолчанию с 2026-09-24; без экрана — как offline); offline — без сети и в своём доме, с уведомлением; as-is — записи не трогать и вернуть перехваченные. /etc/xdg/autostart не трогается никогда. null — не задавать из Nix. См. docs/CONTAINERS.ru.md §5.";
    };

    zoneX11 = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "games" ];
      description = "Устарело: containers.<имя>.permissions.x11. Зоны (по имени), программы которых получают свой X-сервер (xwayland-satellite) — для X11-only программ вроде Steam без контейнеров; значение по умолчанию для контейнеров без своего: контейнер с permissions.x11 = false X-сервера и здесь не получает. X-сервер хоста из зон недоступен всегда. Сами зоны в Nix не описываются: здесь только имена.";
    };

    nixDaemon = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "agents" ];
      description = "Зоны (по имени), которые допускают Nix-демон хоста (nix-shell, nix build) у своих контейнеров: он виден контейнерам без своей настройки и тем, что его просят (containers.<имя>.permissions.nixDaemon); в сети не из списка его не получит ни один контейнер, даже просящий. По умолчанию ни одной: демон качает и собирает в сети хоста, мимо VPN зоны, и производная с фиксированным хешем скачает любой адрес, который назовёт программа. offline не допускает его никогда, и здесь он ничего не значит. Без пересборки — cellward nix-daemon <зона> on (со следующего подъёма экземпляров контейнеров этой сети). Сами зоны в Nix не описываются: здесь только имена.";
    };

    camera = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "calls" ];
      description = "Зоны (по имени), программам которых видны камеры хоста (/dev/video*) — тем, у чьего контейнера нет своей настройки камеры (containers.<имя>.permissions.camera). По умолчанию ни одной: у сеанса на камеры есть право, и программа зоны — тот же пользователь, она снимала бы без вопроса. Зона закрывает камеры всем своим программам, запуск, которому они разрешены, открывает их в своём пространстве монтирования. Без пересборки — cellward camera <зона> on (для программ, запущенных после этого; перезапуск зоны не нужен). Звуковые устройства (/dev/snd) зонам не видны никогда: звук — через фильтр pulse и PipeWire. Сами зоны в Nix не описываются: здесь только имена.";
    };

    audioManager = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "mixer" ];
      description = "Герметичные зоны (по имени), которым вместо ограниченного PipeWire отдаётся pipewire-0 хоста как есть — для микшера или коммутатора (pavucontrol, qpwgraph, EasyEffects). По умолчанию ни одной: такая зона слышит всё, что играет хост, записывает микрофон мимо microphone, двигает и глушит чужие потоки и меняет права других клиентов PipeWire; cellward status и doctor говорят об этом громко. Обычная (негерметичная) зона получает pipewire-0 хоста и без этого — у неё и так systemd --user. Без пересборки — cellward audio-manager <зона> on (со следующего подъёма экземпляров контейнеров этой сети). Сами зоны в Nix не описываются: здесь только имена.";
    };

    pipewirePolicy = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Положить политику WirePlumber для PipeWire зон в ~/.config/wireplumber/wireplumber.conf.d/90-vpn-zones.conf и ~/.local/share/wireplumber/scripts/vpn-zones/policy.lua — для home-manager без NixOS (на NixOS то же делает services.cellward.pipewirePolicy.enable; включённые оба не дублируются). Без политики герметичная зона PipeWire не получает вовсе — звук только через pulse; с ней её программы видят только свои потоки, выходы для звука и — по настройке microphone — микрофоны, и никогда не мониторы. Подействует после перезапуска WirePlumber (systemctl --user restart wireplumber). Политика — скрипт WirePlumber, а WirePlumber ищет скрипты сначала в ~/.local/share/wireplumber, фрагменты — сначала в ~/.config/wireplumber: поэтому в герметичной зоне эти каталоги, ~/.config/pipewire и ~/.local/state/wireplumber только для чтения и создаются заранее, если их нет. Зона из hostFilesWritable может подменить политику для всех зон. См. docs/LEAK-MODEL.md §20.";
    };

    hostFilesWritable = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "dev" ];
      description = "Зоны (по имени), которые допускают, чтобы их герметичные контейнеры писали туда, что хост потом исполняет из дома: автозапуск, юниты, ярлыки, конфиги оболочек и композитора, ~/.ssh — те, что без своей настройки, и те, что просят (containers.<имя>.permissions.hostFilesWritable). По умолчанию это только для чтения: иначе программа без своего дома подложит хосту код в обход зоны. offline не допускает никогда. Точечные файлы, которые home-manager делает ссылками в корне дома (~/.zshrc → store), монтированием не закрыть — их защищает только свой дом контейнера. Без пересборки — cellward host-files <зона> writable. Сами зоны в Nix не описываются: здесь только имена.";
    };

    microphone = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.enum [
          "yes"
          "no"
          "ask"
        ]
      );
      default = { };
      example = {
        calls = "yes";
        offline = "no";
      };
      description = "Может ли программа зоны записывать микрофон (как разрешения в телефоне): имя зоны → yes (без вопроса), no (никогда) или ask — при первой записи программы зоны на хосте спрашивают: разрешить один раз, всегда или отказать. Зона без значения здесь и без своего (cellward microphone <зона> yes|no|ask) — ask; без графической сессии или без ответа за 25 с — отказ. «Всегда» — всей зоне, любой её программе: пишет yes в настройку зоны; для зоны, заданной здесь, его не предлагают. После отказа зону не спрашивают askAgainAfter (по умолчанию 3 минуты). Действует сразу, без перезапуска зоны. Звук, который играет хост (мониторы выходов), зоне не записать никогда. Путь PulseAudio и ограниченный PipeWire герметичной зоны (на нём ask — отказ: там не спрашивают); мимо — сырой pipewire-0 обычной зоны и зоны-менеджера звука (audioManager), а в негерметичной зоне и systemd --user хоста. Сами зоны в Nix не описываются: здесь только имена.";
    };

    screencast = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.enum [
          "yes"
          "no"
          "ask"
        ]
      );
      default = { };
      example = {
        calls = "yes";
        offline = "no";
      };
      description = "Может ли программа зоны транслировать экран через портал: имя зоны → ask (по умолчанию: диалог портала каждый раз, запомнить выбор нельзя), no (каждый вызов портала ScreenCast — отказ с объяснением и строкой в cellward journal) или yes (выбор можно запомнить: следующую трансляцию портал начнёт без диалога). yes действует, только если портал знает зону по имени (xdg-desktop-portal 1.19+, docs/LEAK-MODEL.md §23), иначе — как ask, и в разовом контейнере (--fs-sandbox) тоже как ask. Действует сразу, без перезапуска зоны. Держит фильтр сессионной шины герметичной зоны: программы негерметичной зоны говорят с порталом напрямую, мимо этого переключателя. Без пересборки — cellward screencast <зона> ask|yes|no. Сами зоны в Nix не описываются: здесь только имена.";
    };

    askAgainAfter = lib.mkOption {
      type = lib.types.nullOr askAgainTerm;
      default = null;
      example = "10m";
      description = "Через сколько после отказа снова спросить о разрешении (сейчас — микрофон): до того запросы программ зоны отказаны без вопроса, чтобы программа, которая переподключается после каждого «нет», не держала диалог открытым в ожидании случайного Enter. Срок — число и единица: 30s…1d (45s, 3m, 1h). null — не задавать из Nix (тогда cellward ask-again <срок>, иначе 3m). Действует сразу, без перезапуска зон.";
    };

    questionTimeout = lib.mkOption {
      type = lib.types.nullOr questionTerm;
      default = null;
      example = "never";
      description = "Сколько вопрос брокера (окно запуска из зоны, «открыть в другой сети?») ждёт ответа, прежде чем закрыться отказом: 30s…1d или never — без срока. Вопрос открыт один: пока он ждёт, следующие получают отказ, а не встают в очередь. null — не задавать из Nix (тогда cellward question-timeout <срок>, иначе 2m). Действует со следующего вопроса.";
    };

    protect = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "~/Configurations/my-machine" ];
      description = "Что из настоящего дома не пишет ни один контейнер, кроме тех, кому это явно выдано (cellward container grant или paths контейнера): прежде всего репозиторий конфигурации машины — кто пишет в него, тот при следующей пересборке получает root. Пути внутри дома, ~/… или абсолютные. То, что исполняет сам хост (автозапуск, службы, оболочки, git, ~/bin, конфигурации панелей, терминалов и редакторов), защищено всегда и сюда не пишется. Действует в герметичных контейнерах с настоящим домом, с их следующего подъёма. Без пересборки — cellward protect add|rm <путь>.";
    };

    netlog = {
      keepDays = lib.mkOption {
        type = lib.types.nullOr (lib.types.ints.between 1 3650);
        default = null;
        example = 90;
        description = "Сколько дней хранить журнал соединений контейнеров (с кем соединялась каждая программа, сколько туда и оттуда; ~/.local/state/vpn-zones/netlog/raw). Итоги по дням хранятся год независимо от этого. null — не задавать из Nix (тогда cellward netlog keep <дни>, иначе 30).";
      };
      maxSize = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "[0-9]+ *([KMGT](i?B)?|B)?");
        default = null;
        example = "2G";
        description = "Сколько места журнал соединений может занять (не меньше 1M): сверх — уходят самые старые дни, а день, который один дорос до предела, дальше не пишется. Что наступит раньше — срок keepDays или этот предел, — то и срабатывает. null — не задавать из Nix (тогда cellward netlog cap <размер>, иначе 1G).";
      };
    };

    handshakeCheckAfter = lib.mkOption {
      type = lib.types.nullOr handshakeTerm;
      default = null;
      example = "15s";
      description = "Сколько окно добавления зоны ждёт первого рукопожатия, прежде чем сказать, жив ли туннель: 1s…10m. Решает только, какое уведомление показать: зона остаётся поднятой в любом случае. null — не задавать из Nix (тогда cellward handshake-check <срок>, иначе 6s).";
    };

    hermetic.default = lib.mkOption {
      type = lib.types.nullOr lib.types.bool;
      default = null;
      description = "Герметичны ли зоны без своей настройки: без systemd --user, сессионная шина через фильтр (xdg-dbus-proxy), запуск в других сетях — только через брокер с вопросом человеку. null — не задавать из Nix (тогда действует cellward hermetic --default, иначе вкл.: с 2026-09 зоны герметичны по умолчанию; прежнее поведение — hermetic.default = false или исключения). Своя настройка зоны (cellward hermetic <зона> on|off) важнее умолчания. См. docs/HERMETICITY.ru.md §7.";
    };

    hermetic.exceptions = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "agents" ];
      description = "Зоны (по имени), для которых действует обратное hermetic.default: при default = true — зоны без герметичности (например, зона, чьи программы законно зовут systemd-run --user), при false — герметичные. Негерметичная зона допускает негерметичные контейнеры: такие у неё все без своей настройки и те, что просят (containers.<имя>.permissions.hermetic = false); герметичная не допускает ни одного. offline и запертая зона герметичны всегда. Важнее своей настройки зоны. Требует заданного hermetic.default. Сами зоны в Nix не описываются: здесь только имена.";
    };

    pathShims.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "PATH-шимы: программа, назначенная контейнеру, набранная в терминале, идёт через пикер, как щелчок по ярлыку. Каталог ~/.local/share/vpn-zones/bin добавляется в PATH сессии. Удобство, а не граница: процесс хоста всегда может запустить store-путь напрямую.";
    };

    tunnelWatch.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Раз в минуту проверять, живы ли туннели поднятых зон (`cellward watch`), и присылать уведомление, когда туннель перестал отвечать и когда снова заработал.";
    };

    waylandProxy.enable = lib.mkOption {
      type = lib.types.nullOr lib.types.bool;
      default = null;
      description = "Посредник Wayland между программами и композитором (rust/src/wl_proxy.rs): программа видит только свои окна и протоколы из белого списка. null — не задавать из Nix (тогда cellward wayland-proxy, иначе вкл.). false — композитор слушает для программ сам, как раньше; ограничения security-context остаются.";
    };

    waylandProxy.exceptions = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "someprogram" ];
      description = "Программы (по имени бинаря или id ярлыка), которые запускаются без посредника, если он с ними не работает. Им остаётся ограниченный сокет security-context.";
    };

    frame.colors = lib.mkOption {
      type = lib.types.attrsOf (lib.types.strMatching "#[0-9a-fA-F]{6}");
      default = { };
      example = {
        work = "#3366ff";
        offline = "#808080";
      };
      description = "Цвет рамки, которую посредник Wayland рисует вокруг окон программ зоны (docs/WINDOW-FRAME.md §0а): имя зоны → #rrggbb. Зона без цвета здесь и без своего (cellward frame color <зона> #rrggbb) получает цвет из своего имени — один и тот же на любой машине. Сами зоны в Nix не описываются: здесь только имена. Действует для программ, запущенных после смены.";
    };

    frame.width = lib.mkOption {
      type = lib.types.nullOr (lib.types.ints.between 1 32);
      default = null;
      example = 6;
      description = "Толщина рамки окон программ зон, логические пиксели. null — не задавать из Nix (тогда cellward frame width, иначе 4: целое число пикселей при масштабах 1,25/1,5/1,75/2). Рамка лежит внутри окна: программе достаётся размер меньше на две толщины. Спрятать рамки на время показа экрана — cellward frame hide (переключатель только локальный: его щёлкают туда и обратно).";
    };

    frame.title = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "always"
          "hover"
          "off"
        ]
      );
      default = null;
      example = "hover";
      description = "Полоса заголовка «зона · контейнер» цвета зоны вдоль верха окон программ зон (docs/WINDOW-FRAME.md §0а). always — всегда, внутри окна: программе достаётся высота меньше на полосу; hover — поверх верха содержимого, выезжает, когда указатель у верхнего края окна, места не занимает; off — только обводка. В fullscreen полосы нет в любом режиме. null — не задавать из Nix (тогда cellward frame title, иначе always). Действует для программ, запущенных после смены.";
    };

    frame.style = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "soft"
          "full"
          "tag"
        ]
      );
      default = null;
      example = "tag";
      description = "Вид рамки (docs/WINDOW-FRAME.md §8 «Вид рамки»). soft — мягкие тона цвета зоны (тот же оттенок, меньше насыщенности), обводка в два тона: темнее снаружи, тон заголовка внутри — рамка всегда на виду и не режет глаз; full — сам цвет зоны, как было до 2026-09-28; tag — без обводки, только бирка «зона · контейнер» с кнопками сверху слева, остальная полоса прозрачная и не мешает указателю (программе достаётся высота меньше на полосу, как с заголовком). null — не задавать из Nix (тогда cellward frame style, иначе soft). Действует для программ, запущенных после смены.";
    };

    frame.buttons = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "cellward"
          "gnome"
          "kde"
          "macos"
          "windows"
          "none"
        ]
      );
      default = null;
      example = "macos";
      description = "Вид кнопок заголовка рамки (≡ меню окна, ⇄ другая сеть, × закрыть): cellward — свои квадратные справа; gnome — круглые, как в GNOME (Adwaita); kde — как в KDE (Breeze): значки, круг под указателем; macos — светофор СЛЕВА (закрыть красная, затем жёлтая и зелёная, значки при наведении); windows — прямоугольные справа; none — без кнопок. «Закрыть» под указателем красная в любом виде. null — не задавать из Nix (тогда cellward frame buttons, иначе cellward). Действует для программ, запущенных после смены.";
    };

    frame.radius = lib.mkOption {
      type = lib.types.nullOr (lib.types.ints.between 0 16);
      default = null;
      example = 10;
      description = "Скругление углов окна программы внутри рамки, логические пиксели (0 — квадратные): посредник кладёт поверх углов окна уголки цвета рамки. У бирки (frame.style = \"tag\") углы не скругляются — вокруг нет рамки, с которой уголку слиться. null — не задавать из Nix (тогда cellward frame radius, иначе 0). Действует для программ, запущенных после смены.";
    };

    tray.badge = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.enum [
          "dot"
          "bar"
          "off"
        ]
      );
      default = null;
      example = "bar";
      description = "Метка цвета зоны (или контейнера — цвет рамки) на значках программ зоны в трее: dot — точка в правом нижнем углу, bar — полоска снизу, off — без метки. Рисует фильтр сессионной шины герметичной зоны, пока значок идёт через него: у обычных зон и запусков unconfined метки нет. Значок, заданный именем из темы, получает метку как наложение (OverlayIconPixmap) — его показывает не всякий трей. В подсказке значка добавляется строка «зона · контейнер». Метка — подсказка, а не граница: программа не уберёт её, но может нарисовать в своём значке другую. null — не задавать из Nix (тогда cellward tray badge, иначе dot). Действует со следующей перерисовки значка.";
    };

    compositorRestriction.enable = lib.mkOption {
      type = lib.types.nullOr lib.types.bool;
      default = null;
      description = "Отбирать ли у программ захват экрана, фоновый буфер обмена и эмуляцию ввода (сокет композитора с wp_security_context). false — программы, в том числе в контейнерах со своим домом и в сети unconfined, получают сырой сокет композитора: захват экрана, эмуляцию ввода и список окон — это выход из изоляции через рабочий стол, а не только потеря приватности. null — не задавать из Nix (по умолчанию включено).";
    };

    desktop = {
      windowMenu.key = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.strMatching "((Mod|Super|Ctrl|Control|Alt|Shift)[+])*[A-Za-z0-9_]+"
        );
        default = null;
        example = "Mod+Shift+Z";
        description = "Клавиша меню окна в фокусе (`cellward window-menu`: его сеть и контейнер, закрепить, перезапустить с выбором, закрыть, оборвать зону) — в записи niri: модификаторы Mod, Super, Ctrl, Alt, Shift через +, затем клавиша (имя XKB). Попадает в фрагменты композиторов ниже (desktop.niri, desktop.sway); сама по себе ничего не включает. null — без клавиши.";
      };
      floatWindows = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Окно запуска и меню окна — плавающие (правило по app id vpn-zone-window), а не отдельная колонка или плитка. Попадает в те же фрагменты.";
      };
      niri = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Писать ~/.config/niri/vpn-zones.kdl: клавиша меню окна и правило окон cellward. Подключается строкой `include \"vpn-zones.kdl\"` в config.kdl (niri 25.11+) — её добавляет desktop.niri.includeInConfig, или впиши сам.";
        };
        includeInConfig = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Дописать `include \"vpn-zones.kdl\"` в конец xdg.configFile.\"niri/config.kdl\".text. Только если config.kdl пишет home-manager текстом: иначе home-manager создаст файл из одной этой строки (или откажется затереть твой). Подключённое в конце перекрывает твои привязки той же клавиши.";
        };
      };
      sway.enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Писать ~/.config/sway/vpn-zones.conf: клавиша меню окна и правило окон cellward. С модулем sway из home-manager строка include добавляется в его extraConfig сама; иначе впиши `include ~/.config/sway/vpn-zones.conf`.";
      };
    };

    containers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule containerModule);
      default = { };
      description = "Контейнеры: дом, сеть, программы, доверенные сертификаты (docs/CONTAINERS.ru.md). Состояние с источником каждого значения — `cellward status --json`.";
    };

    main = lib.mkOption {
      type = lib.types.nullOr (lib.types.submodule containerModule);
      default = null;
      example = lib.literalExpression "{ permissions.microphone = \"yes\"; permissions.devices = [ \"usb:1ea7:0907\" ]; }";
      description = "Разрешения настоящего дома («основной»): те же, что у контейнера (permissions.*, focus, frameColor, trust, links), одни во всех сетях — в каждой сети у него своё пространство, а разрешения общие (docs/PERMISSIONS.md §11.15). Своей сети и программ у него нет: home, network и apps здесь не задаются. permissions.paths — запись в защищённое (programs.cellward.protect). Без пересборки — cellward container set|devices|grant main …";
    };
  };

  config = lib.mkIf config.programs.cellward.enable {
  # The window menu's key and the rule that floats our windows, in each
  # compositor's words. The key is written the niri way and checked by the
  # option's type — only modifier names, `+` and a keysym, nothing that could
  # close a KDL string or start a sway command.
  wayland.windowManager.sway.extraConfig = lib.mkIf (
    cfg.desktop.sway.enable && config.wayland.windowManager.sway.enable
  ) (lib.mkAfter "include ${config.xdg.configHome}/sway/vpn-zones.conf");

  # The zone-level permissions that name zones (stage 5 of the container
  # design, 2026-09-28): a container's own now, containers.<name>.permissions
  # (docs/PERMISSIONS.md §11.2). Still read — what a container without its
  # own takes, at its instance's start —, and said to be on the way out.
  # hermetic.default stays the default of them all. The ways around a
  # network (hermetic.exceptions, nixDaemon, hostFilesWritable) are not on
  # the way out (step 1 of the permission model, 2026-09-28, §11.14): they
  # are what a network tolerates, and a container's own asking is in force
  # only where it is tolerated. offline tolerates none.
  warnings =
    lib.optional (lib.elem "offline" (cfg.nixDaemon ++ cfg.hostFilesWritable)) (
      "programs.cellward.nixDaemon, hostFilesWritable: offline не допускает обходов сети "
      + "никогда — там он ничего не значит; контейнеру, которому это нужно, дай сеть"
    )
    ++ lib.optional (cfg.hermetic.default == true && lib.elem "offline" cfg.hermetic.exceptions) (
      "programs.cellward.hermetic.exceptions: offline герметичен всегда — исключение для него "
      + "ничего не значит"
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: c:
        lib.optional
          (
            c.network == "offline"
            && (
              c.permissions.nixDaemon == true
              || c.permissions.hostFilesWritable == true
              || c.permissions.hermetic == false
            )
          )
          (
            "programs.cellward.containers.${name}: сеть offline не допускает обходов сети "
            + "(hermetic = false, nixDaemon, hostFilesWritable) — они у него не действуют"
          )
      ) cfg.containers
    )
    ++ lib.optional (cfg.microphone != { }) (
      "programs.cellward.microphone не действует: сеть больше не решает, записывают ли её "
      + "программы микрофон (docs/PERMISSIONS.md §11.15) — "
      + "programs.cellward.defaults.permissions.microphone для всех без своего слова, "
      + "containers.<имя>.permissions.microphone и main.permissions.microphone — своё"
    )
    ++ lib.optional (cfg.screencast != { }) (
      "programs.cellward.screencast не действует: сеть больше не решает трансляцию экрана "
      + "своих программ (docs/PERMISSIONS.md §11.15) — "
      + "programs.cellward.defaults.permissions.screencast для всех без своего слова, "
      + "containers.<имя>.permissions.screencast и main.permissions.screencast — своё"
    )
    ++ lib.optional (cfg.audioManager != [ ]) (
      "programs.cellward.audioManager устарело: PipeWire хоста без ограничений теперь у "
      + "контейнера — programs.cellward.containers.<имя>.permissions.audioManager (зона "
      + "остаётся значением по умолчанию для контейнеров без своего)"
    )
    ++ lib.optional (cfg.zoneX11 != [ ]) (
      "programs.cellward.zoneX11 устарело: свой X-сервер теперь у контейнера — "
      + "programs.cellward.containers.<имя>.permissions.x11 (зона остаётся значением по "
      + "умолчанию для контейнеров без своего, null; false у контейнера отказывается и от "
      + "X-сервера зоны)"
    );

  assertions =
    lib.mapAttrsToList (name: _: {
      assertion = validName name;
      message = "programs.cellward.containers.${name}: имя контейнера — латиница, цифры, _ . - и не с точки или дефиса";
    }) cfg.containers
    ++ lib.mapAttrsToList (name: c: {
      assertion = c.trust.certificates == [ ] || c.trust.acknowledgeRisk;
      message = "programs.cellward.containers.${name}.trust: дополнительный корневой сертификат позволяет его владельцу читать TLS-трафик программ контейнера — подтверди это: trust.acknowledgeRisk = true";
    }) cfg.containers
    ++ lib.mapAttrsToList (name: c: {
      assertion = c.home == "private" || lib.all (v: lib.hasPrefix "~/" v) c.permissions.paths;
      message = "programs.cellward.containers.${name}.permissions.paths: слою над домом выдаются только пути дома (~/…): вне дома слоя нет, там и так настоящее";
    }) cfg.containers
    ++ lib.mapAttrsToList (name: c: {
      assertion = lib.all (
        scheme: builtins.match "[A-Za-z][A-Za-z0-9+.-]*" scheme != null
      ) (lib.attrNames c.links)
      && lib.all (app: builtins.match "[^-./[:space:]][^/[:space:]]*" app != null) (lib.attrValues c.links);
      message = "programs.cellward.containers.${name}.links: схема ссылки — латиница, цифры, + . - (https, tg…); программа — id ярлыка без пути и пробелов (firefox)";
    }) cfg.containers
    ++ lib.mapAttrsToList (name: c: {
      assertion = c.home != "main" || (lib.all inProtect c.permissions.paths && c.trust.certificates == [ ]);
      message = "programs.cellward.containers.${name}: настоящему дому (home = \"main\") выдаётся только запись в защищённое (paths из programs.cellward.protect), и своих сертификатов у него нет — сертификат лёг бы в настоящий дом";
    }) cfg.containers
    ++ lib.optionals (cfg.main != null) [
      {
        assertion = cfg.main.network == null && cfg.main.apps == [ ];
        message = "programs.cellward.main: у настоящего дома нет своей сети и своих программ — сеть выбирается при запуске, программы закрепляются в окне запуска";
      }
      {
        assertion = lib.all inProtect cfg.main.permissions.paths && cfg.main.trust.certificates == [ ];
        message = "programs.cellward.main: выдаётся только запись в защищённое (paths из programs.cellward.protect), и своих сертификатов у настоящего дома нет";
      }
    ]
    ++ lib.mapAttrsToList (name: c: {
      assertion = lib.all (
        v: !(lib.hasInfix "\n" v) && (lib.hasPrefix "/" v || lib.hasPrefix "~/" v)
      ) c.permissions.paths && lib.all (v: !(lib.hasInfix "\n" v)) c.apps;
      message = "programs.cellward.containers.${name}: каталог в permissions.paths — абсолютный путь или ~/…, без переводов строки (и id программ тоже без них)";
    }) cfg.containers
    ++ [
      {
        assertion = cfg.hermetic.exceptions == [ ] || cfg.hermetic.default != null;
        message = "programs.cellward.hermetic.exceptions: исключения — это зоны с обратным умолчанию значением, поэтому нужно явное hermetic.default (true или false)";
      }
      {
        assertion = lib.all (z: z != "" && !(lib.hasInfix "\n" z)) cfg.hermetic.exceptions;
        message = "programs.cellward.hermetic.exceptions: имя зоны — непустое и без переводов строки";
      }
      {
        assertion = lib.all (z: builtins.match "[^[:space:]]+" z != null) (lib.attrNames cfg.frame.colors);
        message = "programs.cellward.frame.colors: имя зоны — непустое и без пробелов";
      }
      {
        assertion = lib.all (z: builtins.match "[^[:space:]]+" z != null) (lib.attrNames cfg.microphone);
        message = "programs.cellward.microphone: имя зоны — непустое и без пробелов";
      }
      {
        assertion = lib.all (z: builtins.match "[^[:space:]]+" z != null) (lib.attrNames cfg.screencast);
        message = "programs.cellward.screencast: имя зоны — непустое и без пробелов";
      }
      {
        assertion = lib.all (z: z != "" && !(lib.hasInfix "\n" z)) (
          cfg.nixDaemon ++ cfg.hostFilesWritable ++ cfg.camera ++ cfg.audioManager
        );
        message = "programs.cellward.nixDaemon / hostFilesWritable / camera / audioManager: имя зоны — непустое и без переводов строки";
      }
      {
        assertion =
          cfg.desktop.niri.includeInConfig
          -> (
            cfg.desktop.niri.enable
            # Home-manager writes config.kdl as text with more in it than our
            # line — otherwise the "config" would be one include, and niri would
            # start with nothing of the user's.
            && lib.stringLength (lib.trim (config.xdg.configFile."niri/config.kdl".text or ""))
              > lib.stringLength "include \"vpn-zones.kdl\""
          );
        message = "programs.cellward.desktop.niri.includeInConfig: нужно desktop.niri.enable, и config.kdl должен писать home-manager текстом (xdg.configFile.\"niri/config.kdl\".text) — иначе config.kdl стал бы одной строкой include";
      }
      {
        # Где зоны ищут ярлыки, автозапуск и настройки: ~/.local/share и
        # ~/.config. С другим xdg.dataHome/configHome лаунчеры не увидели бы
        # перехваченных ярлыков — каждый щелчок мимо пикера (review 2026-09-25).
        assertion =
          config.xdg.dataHome == "${config.home.homeDirectory}/.local/share"
          && config.xdg.configHome == "${config.home.homeDirectory}/.config";
        message = "programs.cellward: xdg.dataHome и xdg.configHome должны быть по умолчанию (~/.local/share, ~/.config) — перехват ярлыков и настройки cellward живут там";
      }
      {
        assertion = duplicateApps == [ ];
        message = "programs.cellward.containers: программы назначены нескольким контейнерам сразу: ${lib.concatStringsSep ", " duplicateApps}";
      }
    ];

  xdg.configFile = lib.mkMerge [
    (lib.mkIf cfg.desktop.niri.enable {
      "niri/vpn-zones.kdl".text = niriSnippet;
    })
    (lib.mkIf (cfg.desktop.niri.enable && cfg.desktop.niri.includeInConfig) {
      "niri/config.kdl".text = lib.mkAfter ''
        include "vpn-zones.kdl"
      '';
    })
    (lib.mkIf cfg.desktop.sway.enable {
      "sway/vpn-zones.conf".text = swaySnippet;
    })
    # The WirePlumber policy for the zones' PipeWire (docs/LEAK-MODEL.md §20),
    # for a home-manager without NixOS: the same fragment the NixOS module
    # writes, under the same name — the user's copy replaces the system's.
    (lib.mkIf cfg.pipewirePolicy {
      "wireplumber/wireplumber.conf.d/90-vpn-zones.conf".source = ./wireplumber/90-vpn-zones.conf;
    })
  ];

  xdg.dataFile = lib.mkIf cfg.pipewirePolicy {
    "wireplumber/scripts/vpn-zones/policy.lua".source = ./wireplumber/policy.lua;
  };

  # Объявленное — в ~/.config/vpn-zones/declared, а не в xdg.configHome: CLI,
  # держатель и генератор ярлыков читают именно этот путь, и при своём
  # xdg.configHome объявленное молча не применялось бы — привязки контейнеров
  # к сетям тоже (review 2026-09-24).
  home.file = lib.mkMerge [
    (lib.mkIf (cfg.defaults.network != null) {
      ".config/vpn-zones/declared/default".text = cfg.defaults.network;
    })
    (lib.mkIf (cfg.defaults.container != null) {
      ".config/vpn-zones/declared/default-profile".text = cfg.defaults.container;
    })
    (lib.mkIf (cfg.launcher.mode != null) {
      ".config/vpn-zones/declared/mode".text = cfg.launcher.mode;
    })
    (lib.mkIf (cfg.zoneX11 != [ ]) {
      ".config/vpn-zones/declared/zone-x11".text = lib.concatStringsSep "\n" cfg.zoneX11 + "\n";
    })
    (lib.mkIf (cfg.hermetic.default != null) {
      ".config/vpn-zones/declared/hermetic-default".text = if cfg.hermetic.default then "on" else "off";
    })
    (lib.mkIf (cfg.nixDaemon != [ ]) {
      ".config/vpn-zones/declared/nix-daemon".text = lib.concatStringsSep "\n" cfg.nixDaemon + "\n";
    })
    (lib.mkIf (cfg.camera != [ ]) {
      ".config/vpn-zones/declared/camera".text = lib.concatStringsSep "\n" cfg.camera + "\n";
    })
    (lib.mkIf (cfg.audioManager != [ ]) {
      ".config/vpn-zones/declared/audio-manager".text = lib.concatStringsSep "\n" cfg.audioManager + "\n";
    })
    (lib.mkIf (cfg.hostFilesWritable != [ ]) {
      ".config/vpn-zones/declared/host-files-writable".text =
        lib.concatStringsSep "\n" cfg.hostFilesWritable + "\n";
    })
    (lib.mkIf (cfg.hermetic.exceptions != [ ]) {
      ".config/vpn-zones/declared/hermetic-exceptions".text =
        lib.concatStringsSep "\n" cfg.hermetic.exceptions + "\n";
    })
    (lib.mkIf cfg.pathShims.enable {
      ".config/vpn-zones/declared/path-shims".text = "on";
    })
    (lib.mkIf (cfg.autostart.unassigned != null) {
      ".config/vpn-zones/declared/autostart".text = cfg.autostart.unassigned;
    })
    (lib.mkIf (cfg.interception.userEntries != null) {
      ".config/vpn-zones/declared/user-entries".text = cfg.interception.userEntries;
    })
    (lib.mkIf (cfg.waylandProxy.enable != null) {
      ".config/vpn-zones/declared/wayland-proxy".text = if cfg.waylandProxy.enable then "on" else "off";
    })
    (lib.mkIf (cfg.waylandProxy.exceptions != [ ]) {
      ".config/vpn-zones/declared/wayland-no-proxy".text =
        lib.concatStringsSep "\n" cfg.waylandProxy.exceptions + "\n";
    })
    (lib.mkIf (cfg.frame.colors != { }) {
      ".config/vpn-zones/declared/frame-colors".text = lib.concatStrings (
        lib.mapAttrsToList (zone: color: "${zone} ${color}\n") cfg.frame.colors
      );
    })
    (lib.mkIf (cfg.microphone != { }) {
      ".config/vpn-zones/declared/microphone".text = lib.concatStrings (
        lib.mapAttrsToList (zone: value: "${zone} ${value}\n") cfg.microphone
      );
    })
    (lib.mkIf (cfg.screencast != { }) {
      ".config/vpn-zones/declared/screencast".text = lib.concatStrings (
        lib.mapAttrsToList (zone: value: "${zone} ${value}\n") cfg.screencast
      );
    })
    (lib.mkIf (cfg.askAgainAfter != null) {
      ".config/vpn-zones/declared/ask-again".text = cfg.askAgainAfter;
    })
    (lib.mkIf (cfg.questionTimeout != null) {
      ".config/vpn-zones/declared/question-timeout".text = cfg.questionTimeout;
    })
    (lib.mkIf (cfg.defaults.permissions.microphone != null || cfg.defaults.permissions.screencast != null) {
      ".config/vpn-zones/declared/defaults.conf".text = lib.concatStrings (
        lib.optional (cfg.defaults.permissions.microphone != null) "microphone = ${cfg.defaults.permissions.microphone}\n"
        ++ lib.optional (cfg.defaults.permissions.screencast != null) "screencast = ${cfg.defaults.permissions.screencast}\n"
      );
    })
    (lib.mkIf (cfg.protect != [ ]) {
      ".config/vpn-zones/declared/protect".text = lib.concatMapStrings (p: "${p}\n") cfg.protect;
    })
    (lib.mkIf (cfg.netlog.keepDays != null) {
      ".config/vpn-zones/declared/netlog-keep".text = toString cfg.netlog.keepDays;
    })
    (lib.mkIf (cfg.netlog.maxSize != null) {
      ".config/vpn-zones/declared/netlog-cap".text = cfg.netlog.maxSize;
    })
    (lib.mkIf (cfg.handshakeCheckAfter != null) {
      ".config/vpn-zones/declared/handshake-check".text = cfg.handshakeCheckAfter;
    })
    (lib.mkIf (cfg.frame.width != null) {
      ".config/vpn-zones/declared/frame-width".text = toString cfg.frame.width;
    })
    (lib.mkIf (cfg.frame.title != null) {
      ".config/vpn-zones/declared/frame-title".text = cfg.frame.title;
    })
    (lib.mkIf (cfg.frame.style != null) {
      ".config/vpn-zones/declared/frame-style".text = cfg.frame.style;
    })
    (lib.mkIf (cfg.frame.buttons != null) {
      ".config/vpn-zones/declared/frame-buttons".text = cfg.frame.buttons;
    })
    (lib.mkIf (cfg.tray.badge != null) {
      ".config/vpn-zones/declared/tray-badge".text = cfg.tray.badge;
    })
    (lib.mkIf (cfg.frame.radius != null) {
      ".config/vpn-zones/declared/frame-radius".text = toString cfg.frame.radius;
    })
    (lib.mkIf (cfg.compositorRestriction.enable != null) {
      ".config/vpn-zones/declared/wayland-sandbox".text = if cfg.compositorRestriction.enable then "on" else "off";
    })
    (lib.mapAttrs' (
      name: c: lib.nameValuePair ".config/vpn-zones/declared/containers/${name}.conf" { text = renderContainer name c; }
    ) cfg.containers)
    (lib.mkIf (cfg.main != null) {
      ".config/vpn-zones/declared/containers/main.conf".text = renderContainer "main" (
        cfg.main
        // {
          home = "main";
          network = null;
          apps = [ ];
        }
      );
    })
  ];

  # Каталоги данных объявленных контейнеров: без них запуск в слое отказался
  # бы («контейнера нет — создай»), а слой доверия искал бы, куда положить
  # бандл. Один каталог на контейнер, какой бы ни был дом; его содержимое
  # готовит запуск по виду дома (container::prepare_data). У основного дома
  # своих данных нет.
  home.activation.vpnZoneContainers = lib.hm.dag.entryAfter [ "writeBoundary" ] (
    lib.concatStrings (
      lib.mapAttrsToList (
        name: c:
        lib.optionalString (c.home != "main") ''
          $DRY_RUN_CMD mkdir -p ${lib.escapeShellArg "${profilesDir}/${name}"}
        ''
      ) cfg.containers
    )
  );

  home.packages = [
    cellward # и псевдонимы cw, vpn-zone
    vpn-zone-sync
    vpn-zone-pick
    cellward-gui # и псевдоним vpn-zone-gui
    # Помощники Rust-ядра: vpn-zone-core (подкоманды zone-holder, profile-run,
    # sync, wl-sandbox и fs-sandbox — их зовут юнит и сам CLI) и
    # vpn-zone-seccomp (генератор фильтра, он же selftest). Сам CLI, пикер и
    # окна приходят обёртками выше — крейт целиком сюда класть нельзя, в нём
    # есть и bin/vpn-zone, и bin/vpn-zone-pick, и bin/vpn-zone-gui.
    vpn-zone-helpers
    cellward-completions # Tab-дополнение zsh/bash (см. определение выше)
    passtPatched # userspace-сеть для зон (с патчем привязки к интерфейсу)
    # Клиент зон [OpenConnect]. В профиль он кладётся не ради самих зон — им
    # хватает пути в ExecStart юнита, — а ради ОДНОЙ операции, которую человек
    # делает руками: узнать отпечаток сертификата корпоративного шлюза.
    # Клиент печатает готовую строку `--servercert pin-sha256:…`, и считать её
    # чем-то другим значит однажды разойтись с ним в формате (README).
    # Замыкание от этого не растёт: юнит и так тянет тот же store-путь.
    pkgs.openconnect
    pkgs.kdePackages.kdialog # файлпикер в стиле остального десктопа
  ];

  # Шаблонный юнит: одна зона — один экземпляр. Останавливается по обычному
  # systemctl --user stop, переживает выход из графической сессии (зона живёт,
  # пока её не погасить), логи — journalctl --user -u vpn-zone@<имя>.
  systemd.user.services."vpn-zone@" = {
    Unit = {
      Description = "VPN-зона %i (сетевое пространство с туннелем)";
      # Обновление не рвёт сеть работающим зонам: home-manager (sd-switch)
      # оставляет запущенный экземпляр как есть, а не перезапускает его —
      # перезапуск держателя оставил бы программы зоны в пространстве без
      # туннеля. Новые запуски идут уже через новый cellward; сама зона
      # переходит на новую сборку, когда её перезапустят (cellward down/up),
      # и до тех пор doctor и status говорят, что она на прошлой сборке.
      # sd-switch читает это из НОВОГО юнита: первое же обновление на версию
      # с этой строкой уже не трогает работающие зоны.
      X-SwitchMethod = "keep-old";
      # Сокет брокера — до зоны: держатель переносит его в зону, если он
      # есть к её подъёму (zone.rs, seal_runtime).
      Wants = [ "vpn-zone-broker.socket" ];
      After = [
        "network-online.target"
        "vpn-zone-broker.socket"
      ];
    };
    Service = {
      # READY=1 — когда зона готова (держатель пишет `ready`): `systemctl
      # start`, а с ним `cellward up` и запуск в опущенную зону, ждёт ровно
      # готовности или неудачи, сколько бы ни шла настройка. Своих часов у
      # нас нет, и срока старта у юнита тоже: на загруженной машине зона
      # поднимается дольше, а не «не поднимается». Зависший старт обрывает
      # человек — `cellward down` (systemctl stop).
      Type = "notify";
      TimeoutStartSec = "infinity";
      # Держатель зоны — подкоманда rust-ядра (rust/src/zone.rs). Пути
      # инструментов подставляются здесь, а не ищутся в PATH: часть кода
      # исполняется внутри namespace, где PATH может быть каким угодно.
      # Исключение — newuidmap/newgidmap: их держатель ищет ИМЕННО в PATH, как
      # это делал unshare(1), потому что setuid-обёртки лежат в /run/wrappers/bin
      # и в store их нет.
      #
      # --nft — второй эшелон (docs/LEAK-MODEL.md): в app-ns выход только через
      # туннель, в uplink-ns наружу только пакеты самого туннеля до endpoint.
      # Не поднявшийся фаерволл зону НЕ роняет: это страховка поверх топологии,
      # и держатель громко пишет об этом в журнал.
      #
      # --openconnect нужен только зонам с секцией [OpenConnect]; зона на
      # WireGuard/AmneziaWG на этот путь ни разу не смотрит.
      ExecStart =
        "${vpn-zone-rust}/bin/vpn-zone-core zone-holder"
        + " --ip ${iproute} --awg ${awg} --wg ${wg} --pasta ${pasta} --nft ${nft}"
        # Мост для экземпляров контейнеров (rust/src/bridge.rs): зона
        # запускает passt --fd на каждый экземпляр, который везёт.
        + " --passt ${passtBin}"
        + " --openconnect ${openconnect} --dbus-proxy ${dbusProxy}/bin/xdg-dbus-proxy"
        # Фильтр шины герметичной зоны отдаёт ссылки брокеру (PERMISSIONS
        # §11.13); opener остался ему на случай песочницы на хосте.
        + " --opener ${vpn-zone-opener}"
        # Чем фильтр звука зоны спрашивает, дать ли программе микрофон
        # (rust/src/microphone.rs): спрашивает в окружении юнита — есть ли в
        # нём WAYLAND_DISPLAY/DISPLAY, есть ли кого спросить.
        + " --kdialog ${kdialog}"
        # И окно запуска: вопрос о микрофоне в нём защищён (ничего не
        # принимается, пока человек не побыл с вопросом перед глазами),
        # kdialog — только если окна нет.
        + " --window ${vpn-zone-window}/bin/vpn-zone-window"
        # Exec ярлыка зоны для портала (~/.local/share/applications/
        # cellward.zone.<зона>.desktop, rust/src/desktop.rs): GLib берёт ярлык,
        # только если найдёт его программу, а PATH портала может её не знать.
        # Профильный путь, как runner манифеста: не протухает при пересборке.
        + " --runner ${config.home.profileDirectory}/bin/cellward %i";
      Restart = "no";
      # KillMode=control-group по умолчанию: гасим зону — гаснет и pasta, и всё,
      # что в зоне работало, теряет сеть. Это и есть kill switch.
    };
  };

  # Экземпляр контейнера (rust/src/instance.rs, docs/CONTAINERS.md §3.6):
  # у запущенного контейнера свои пространства имён — пользователь, сеть,
  # точки монтирования, IPC — со всеми покрытиями зоны, свой /dev и свои
  # помощники (шина, звук, PipeWire). Этап 1 (2026-09-27): выхода у
  # экземпляра нет — в него идёт каждый запуск с сетью offline, а зона
  # offline для запусков больше не поднимается. Имя экземпляра — id
  # контейнера (systemd-экранированный, отсюда %I в ExecStart).
  systemd.user.services."vpn-zone-container@" = {
    Unit = {
      Description = "Экземпляр контейнера %I";
      # Обновление не трогает работающие экземпляры: их остановка закрыла бы
      # программы контейнера. Новая сборка — со следующего запуска.
      X-SwitchMethod = "keep-old";
      # Брокер — дверь наружу и из экземпляра: его сокет держатель
      # переносит внутрь при подъёме.
      Wants = [ "vpn-zone-broker.socket" ];
      After = [ "vpn-zone-broker.socket" ];
    };
    Service = {
      # READY=1 — когда пространство экземпляра готово (`ready`); своих
      # часов у старта нет, как у зоны.
      Type = "notify";
      TimeoutStartSec = "infinity";
      # Своё дерево cgroup — задел под следующие этапы (живое переключение
      # сети держит «стену эпох» на cgroup): держатель и его помощники — в
      # подгруппе infra. На этапе 1 программы остаются в своих областях
      # (из сеанса входа ядро не даёт перенести процесс в дерево
      # user@.service), и экземпляр узнаёт свои программы по пространству
      # имён пользователя.
      Delegate = "yes";
      DelegateSubgroup = "infra";
      # SIGTERM — только держателю: он сам закрывает программы контейнера
      # (TERM и ждёт), потом своё пространство. Единственные часы здесь —
      # TimeoutStopSec самого systemd для программы, которая не закрывается.
      KillMode = "mixed";
      Restart = "no";
      ExecStart =
        "${vpn-zone-rust}/bin/vpn-zone-core container-holder"
        + " --ip ${iproute} --nft ${nft} --dbus-proxy ${dbusProxy}/bin/xdg-dbus-proxy"
        + " --opener ${vpn-zone-opener}"
        + " --kdialog ${kdialog}"
        + " --window ${vpn-zone-window}/bin/vpn-zone-window"
        + " --runner ${config.home.profileDirectory}/bin/cellward %I";
    };
  };

  # Ярлыки пересобираются: раз в полчаса, при входе в сессию и при изменении
  # каталогов с .desktop (после nixos-rebuild там появляются новые программы).
  systemd.user.services.vpn-zone-desktop-sync = {
    Unit.Description = "Пересборка ярлыков VPN-зон";
    Service = {
      Type = "oneshot";
      ExecStart = "${vpn-zone-sync}/bin/vpn-zone-sync";
    };
  };

  # Живость туннелей: зона с мёртвым туннелем не течёт, но и человеку об этом
  # никто не говорит — браузер просто крутится. Раз в минуту смотрим счётчики
  # и уведомляем при смерти и при возвращении (rust/src/watch.rs).
  home.sessionPath = lib.mkIf cfg.pathShims.enable [
    "${config.home.homeDirectory}/.local/share/vpn-zones/bin"
  ];

  # Брокер: единственная дверь наружу из герметичной зоны (rust/src/broker.rs).
  # Кто просит — узнаёт по сетевому namespace процесса, запуск в ту же зону —
  # без вопроса, в другую сеть — только после подтверждения человеком.
  # Брокер активируется сокетом: сокет есть с момента, как его захотел
  # менеджер пользователя или любая зона (vpn-zone@ его требует), даже если
  # home-manager положил юниты уже после того, как менеджер прошёл
  # default.target (так было в CI: служба просто не запустилась). Зоны теперь
  # герметичны по умолчанию, и брокер — их единственная дверь наружу.
  systemd.user.sockets.vpn-zone-broker = {
    Unit = {
      Description = "Сокет брокера запусков из герметичных VPN-зон";
      # Держатель переносит этот сокет в зону при её подъёме: пересозданный
      # при обновлении сокет работающие зоны уже не увидели бы, и брокер —
      # их единственная дверь наружу — пропал бы для них до перезапуска.
      # Сокет остаётся прежним; сама служба брокера обновляется как обычно.
      X-SwitchMethod = "keep-old";
    };
    Socket = {
      ListenStream = "%t/vpn-zones/broker";
      SocketMode = "0600";
      DirectoryMode = "0700";
    };
    Install.WantedBy = [ "sockets.target" ];
  };
  systemd.user.services.vpn-zone-broker = {
    Unit = {
      Description = "Брокер запусков из герметичных VPN-зон";
      Requires = [ "vpn-zone-broker.socket" ];
      After = [ "vpn-zone-broker.socket" ];
    };
    Service = {
      ExecStart = "${cellward}/bin/cellward _broker";
      Restart = "on-failure";
    };
  };

  systemd.user.services.vpn-zone-watch = lib.mkIf cfg.tunnelWatch.enable {
    Unit.Description = "Проверка живости туннелей VPN-зон";
    Service = {
      Type = "oneshot";
      ExecStart = "${cellward}/bin/cellward watch";
    };
  };

  systemd.user.timers.vpn-zone-watch = lib.mkIf cfg.tunnelWatch.enable {
    Unit.Description = "Ежеминутная проверка живости туннелей VPN-зон";
    Timer = {
      OnStartupSec = "1m";
      OnUnitActiveSec = "1m";
      AccuracySec = "10s";
    };
    Install.WantedBy = [ "timers.target" ];
  };

  systemd.user.timers.vpn-zone-desktop-sync = {
    Unit.Description = "Регулярная пересборка ярлыков VPN-зон";
    Timer = {
      OnStartupSec = "2m";
      OnUnitActiveSec = "30m";
      Persistent = true;
    };
    Install.WantedBy = [ "timers.target" ];
  };

  # Пересборка ярлыков сразу после активации. Без этого шага порядок был
  # случайным: таймер или path-юнит могли отработать ДО подмены профиля, ярлыки
  # оставались в старом формате, а пикер приезжал новый — и запуск программ
  # ломался до следующего срабатывания таймера.
  home.activation.vpnZoneSync = lib.hm.dag.entryAfter [ "linkGeneration" ] ''
    $DRY_RUN_CMD ${vpn-zone-sync}/bin/vpn-zone-sync || true
  '';

  systemd.user.paths.vpn-zone-desktop-sync = {
    Unit.Description = "Следить за появлением новых .desktop";
    Path = {
      PathChanged = [
        "${config.home.homeDirectory}/.local/share/applications"
        # Wine кладёт ярлык каждой установленной программы в подкаталог
        # (wine/Programs/<программа>/): его тоже перехватываем сразу. Глубже
        # слежения нет (PathChanged не рекурсивен) — там догоняет таймер.
        "${config.home.homeDirectory}/.local/share/applications/wine/Programs"
        # Программа, включившая свой автозапуск, перехватывается сразу, а не
        # через полчаса — до следующего входа в сессию успевает наверняка.
        "${config.home.homeDirectory}/.config/autostart"
        "/etc/profiles/per-user/${config.home.username}/share/applications"
        "/run/current-system/sw/share/applications"
      ];
      Unit = "vpn-zone-desktop-sync.service";
    };
    Install.WantedBy = [ "paths.target" ];
  };

  xdg.desktopEntries."vpn-zone-remove" = {
    name = "Удалить VPN-зону";
    comment = "Остановить и удалить зону вместе с её конфигом";
    exec = guiExec "remove";
    icon = "network-vpn";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  # Имена всех наших ярлыков начинаются с vpn-zone- — значит генератор ярлыков
  # их не берёт на вход и сам себя не перехватывает (docs/GOTCHAS.md §10).
  xdg.desktopEntries."vpn-zone-profile-add" = {
    name = "Создать контейнер";
    comment = "Завести отдельное хранилище настроек и сессий заранее, до запуска программ";
    exec = guiExec "profile-add";
    icon = "folder-new";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-kill" = {
    name = "Оборвать VPN-зону";
    comment = "Сразу убить все программы зоны и опустить её — например, прекратить удалённый доступ";
    exec = guiExec "kill";
    icon = "process-stop";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-settings" = {
    name = "Настройки cellward";
    comment = "Сеть и контейнер по умолчанию, поведение ярлыков, замки зон";
    exec = guiExec "settings";
    icon = "configure";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-profile-rm" = {
    name = "Удалить контейнер (слой над домом)";
    comment = "Снести накопленный слой над домом — у одного контейнера или у всех сразу";
    exec = guiExec "profile-rm";
    icon = "edit-delete";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-containers" = {
    name = "Контейнеры cellward";
    comment = "Сеть контейнера, объединение двух контейнеров, выданные каталоги, расход";
    exec = guiExec "containers";
    icon = "folder-network";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-monitor" = {
    name = "Сеть cellward";
    comment = "Что отдают и принимают контейнеры: сейчас, за день, за месяц";
    exec = guiExec "monitor";
    icon = "network-transmit-receive";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-forget" = {
    name = "Сбросить сети программ";
    comment = "Забыть, в какой сети запускать программу — у одной или у всех сразу";
    exec = guiExec "forget";
    icon = "edit-clear-history";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  # Тот самый пункт в лаунчере (Super+Space → «VPN»).
  xdg.desktopEntries."vpn-zone-add" = {
    name = "Добавить VPN-зону (AmneziaWG)";
    comment = "Выбрать .conf и создать сетевую зону; ко всем приложениям появятся ярлыки «(имя зоны)»";
    exec = guiExec "add";
    icon = "network-vpn";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };
  };
}
