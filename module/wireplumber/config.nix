# Политика WirePlumber для PipeWire зон (docs/LEAK-MODEL.md §17): разделы
# фрагмента 90-vpn-zones.conf. Один источник для обоих путей — NixOS
# (services.vpn-zones.pipewirePolicy, через services.pipewire.wireplumber.
# extraConfig/extraScripts) и home-manager без NixOS (programs.vpn-zones.
# pipewirePolicy, файлы в ~/.config/wireplumber и ~/.local/share/wireplumber).
# Имена файлов у обоих путей одни: включённые разом, они не дублируются —
# фрагмент и скрипт с тем же именем в каталоге пользователя заменяют
# системные.
{
  # Скрипт — в профиле main, через виртуальный компонент, который его
  # «хочет» (wants), а не требует: сломанный скрипт не должен оставить без
  # звука весь сеанс, а «optional» в профиле сам ничего не загружает. Не
  # загрузился — нет и метки vpn-zones.policy, и помощник зоны сокет не
  # отдаёт: зоне закрыто (только pulse).
  "wireplumber.components" = [
    {
      name = "vpn-zones/policy.lua";
      type = "script/lua";
      provides = "custom.vpn-zones.policy";
    }
    {
      type = "virtual";
      provides = "custom.vpn-zones";
      wants = [ "custom.vpn-zones.policy" ];
    }
  ];
  "wireplumber.profiles" = {
    main = {
      "custom.vpn-zones" = "required";
    };
  };
  # Клиенту зоны по умолчанию — никаких прав: без этого правила WirePlumber
  # 0.5.14 дал бы «restricted» чтение и исполнение на всё. Права раздаёт
  # скрипт, по объекту. Метку он ставит, только если видит это правило в силе.
  "access.rules" = [
    {
      matches = [ { "pipewire.sec.engine" = "vpn-zone"; } ];
      actions = {
        update-props = {
          default_permissions = "-";
        };
      };
    }
  ];
}
