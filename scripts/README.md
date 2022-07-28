# Скрипты для JUNOS

* must-filter.slax - проверяет что на интерфейсе установлен input filter и генерирует warning если это не так

## Как установить скрипт:

* Скопировать скрипт на свич:
```
% scp must-filter.slax switchname:/var/db/scripts/commit/must-filter.slax
```

* Если в стеке несколько юнитов, надо распространить скрипт на них все:
```
> file copy /var/db/scripts/commit/must-filter.slax fpc1:/var/db/scripts/commit/must-filter.slax
```

* Включить скрипт в конфиге:
```
# set system scripts commit file must-filter.slax
# commit check
```

# Ссылки по теме

* https://github.com/Juniper/junoscriptorium
* http://network-arborist.blogspot.com/2014/04/junos-scripts-on-ex-virtual-chassis.html
* http://www.libslax.org/the-slax-language