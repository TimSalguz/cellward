{
  description = "cellward (прежнее имя — vpn-zones): сетевые зоны с VPN, контейнеры данных и песочницы для запуска программ — из-под пользователя, без root";

  outputs = { self }: {
    homeModules.default = ./module;
    homeManagerModules.default = ./module; # старое имя, для совместимости
    # Модуль NixOS: единый вход services.cellward.enable (module/entry.nix —
    # модули ядра, политика PipeWire, модуль home-manager всем пользователям
    # home-manager) и системный уровень services.cellward.system (M10,
    # docs/SYSTEM.md): зоны с загрузки для служб и NixOS-контейнеров.
    # Необязательный: без него всё rootless, как было.
    nixosModules.default = ./module/nixos.nix;

    # Проверить, что модуль хотя бы разбирается, можно так:
    #   nix eval --impure --expr '(import <nixpkgs/lib>).evalModules { modules = [ ./module ]; }'
  };
}
