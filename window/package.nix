# vpn-zone-window — окно запуска (сеть и контейнер программы рядом). Крейт
# отдельный от rust/: инструментарий окна (iced) большой, и ядро vpn-zones не
# должно расти из-за него. Пикер зовёт этот бинарь, как зовёт kdialog, и без
# него спрашивает kdialog'ом.
{
  lib,
  rustPlatform,
  patchelf,
  makeFontsConf,
  dejavu_fonts,
  noto-fonts-color-emoji,
  wayland,
  libxkbcommon,
  libx11,
  libxcursor,
  libxrandr,
  libxi,
}:

let
  # winit подгружает эти библиотеки через dlopen, а не линковкой: трассировка
  # зависимостей их не видит, общей /usr/lib в NixOS нет. Путь вписывается в
  # сам бинарь (RPATH), а не в LD_LIBRARY_PATH обёрткой — тот утёк бы в
  # дочерние процессы. Отрисовка программная (tiny-skia): ни GL, ни Vulkan не
  # нужны.
  runtimeLibs = [
    wayland
    libxkbcommon
    libx11
    libxcursor
    libxrandr
    libxi
  ];
  # Шрифты окна — свои, короткий список. iced при каждом запуске читает ВСЕ
  # шрифты системы (cosmic-text: «до секунды даже в release»), а у живой
  # машины их больше тысячи: под нагрузкой окно открывалось секундами
  # (владелец, 2026-09-26). Основной шрифт встроен (Fira Sans: латиница,
  # кириллица); отсюда — только запасные для знаков (● ○ ▸ ⚠ ⓘ) и значков
  # (🔒 🗑 ➕).
  fontsConf = makeFontsConf {
    fontDirectories = [
      dejavu_fonts
      noto-fonts-color-emoji
    ];
  };
in
rustPlatform.buildRustPackage {
  pname = "vpn-zone-window";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  # Путь вшивается в бинарь при сборке (`option_env!` в main.rs), и окно
  # само ставит себе FONTCONFIG_FILE: без обёртки — у той процесс назывался
  # бы `.vpn-zone-window-wrapped`, и его не находил бы никто, кто ищет окно
  # по имени (VM-тест, pgrep).
  VPN_ZONE_WINDOW_FONTS = fontsConf;

  nativeBuildInputs = [ patchelf ];

  postFixup = ''
    patchelf --add-rpath ${lib.makeLibraryPath runtimeLibs} $out/bin/vpn-zone-window
  '';

  meta = {
    description = "The launch window of vpn-zones: the network and the container of a program";
    license = lib.licenses.mit;
    mainProgram = "vpn-zone-window";
    platforms = lib.platforms.linux;
  };
}
