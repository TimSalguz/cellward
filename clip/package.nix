# cellward-clip — история буфера обмена по контейнерам: зашифрованное
# хранилище с поиском (clipstore) и демон, который пишет в него каждое
# копирование (`cellward-clip daemon`). Крейт отдельный от rust/, как окно:
# криптография, индекс и движок выражений ядру не нужны.
{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "cellward-clip";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ../shared/clipboard_client.rs
      ../shared/clipboard_endpoint.rs
    ];
  };
  sourceRoot = "source/clip";

  cargoLock.lockFile = ./Cargo.lock;

  # Тест на десять миллионов записей помечен #[ignore]; остальные — быстрые.
  meta = {
    description = "cellward's clipboard history by container: an encrypted store, its search and its recorder";
    license = lib.licenses.mit;
    mainProgram = "cellward-clip";
    platforms = lib.platforms.linux;
  };
}
