# Rust-крейт vpn-zones: пять бинарей (vpn-zone-seccomp, vpn-zone-core, vpn-zone,
# vpn-zone-pick, vpn-zone-gui). Общий для обоих модулей — home-manager
# (module/default.nix) и NixOS (module/nixos.nix, системный уровень M10).
# Текст деривации перенесён сюда без изменений, поэтому store-путь прежний.
{
  lib,
  rustPlatform,
  pkg-config,
  libseccomp,
}:

rustPlatform.buildRustPackage {
  pname = "vpn-zone-rust";
  version = "0.1.0";
  # Крейт — сосед этого файла в репозитории. В store кладём только исходники:
  # попади туда ещё и target/ (появляется, стоит один раз запустить cargo
  # руками), каждая пересборка тащила бы в store гигабайты и меняла хеш
  # деривации.
  src = lib.fileset.toSource {
    root = ./rust;
    fileset = lib.fileset.unions [
      ./rust/Cargo.toml
      ./rust/Cargo.lock
      ./rust/src
      ./rust/tests
    ];
  };
  cargoLock.lockFile = ./rust/Cargo.lock;
  # libseccomp-sys линкуется с системной libseccomp, а её версию ищет
  # pkg-config (build.rs крейта libseccomp).
  #
  # А вот libwayland здесь НЕТ, и это осознанный выбор: у wayland-backend
  # фича client_system по умолчанию выключена, то есть wayland-client говорит
  # по проводному протоколу сам, на Rust. Ни линковки, ни dlopen — значит
  # нечему разъехаться с версией композитора и нечего добавлять в buildInputs.
  # Включит кто-нибудь client_system в rust/Cargo.toml — сюда придётся
  # дописать wayland.
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ libseccomp ];
  # Тесты гоняет CI (job rust). Здесь они выключены сознательно: selftest
  # грузит seccomp-фильтр в собственный процесс, а что разрешает песочница
  # сборки nix — зависит от демона; ломать этим пересборку системы нельзя.
  doCheck = false;
  meta.mainProgram = "vpn-zone-seccomp";
}
