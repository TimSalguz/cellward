# vpn-zone-window — окно запуска (сеть и контейнер программы рядом). Крейт
# отдельный от rust/: инструментарий окна (iced) большой, и ядро vpn-zones не
# должно расти из-за него. Пикер зовёт этот бинарь, как зовёт kdialog, и без
# него спрашивает kdialog'ом.
{
  lib,
  rustPlatform,
  patchelf,
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
