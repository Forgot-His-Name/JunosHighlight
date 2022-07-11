# JunosHighlight
Syntax highlighting for junos configs

* junfire.rb is a rouge lexer for firewall relates subset of commands for junos
* jun.xml is a Kate highlithing for same purpose

how to use rouge lexer:
```
rougify -r ./junfire.rb config.fw
```

how to use with Kate: put jun.xml to your ~/.local/share/org.kde.syntax-highlighting/syntax/ or %USERPROFILE%\AppData\Local\org.kde.syntax-highlighting\syntax directory
