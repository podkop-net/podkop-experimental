# podkop-exp

[Русский](README.ru.md)

A place to test new functionality of [podkop](https://github.com/itdoginfo/podkop). What is tried here may later go to podkop, change, or go away.

podkop-exp takes podkop's settings (`/etc/config/podkop`) and its LuCI page, and is installed instead of the podkop package: the two do not work together. Its backend is written in Go and has sing-box inside, so no sing-box package is needed.

## Install

OpenWrt 24.10 or newer, at least 80 MB of RAM. In the router's shell:

```sh
sh <(wget -O - https://raw.githubusercontent.com/podkop-net/podkop-experimental/main/install.sh)
```

The installer checks the router, offers to remove podkop and the packages that conflict with podkop-exp (and, if the flash is short, sing-box packages podkop-exp does not need), then installs podkop-exp and its page, with its Russian translation if you want it. The settings of podkop are converted to those of podkop-exp; the file as it was stays as `/etc/config/podkop.pre-0.8.8`.

Back to podkop: remove `podkop-exp`, `luci-app-podkop-exp` and `luci-i18n-podkop-exp-ru`, put the old settings back with `mv /etc/config/podkop.pre-0.8.8 /etc/config/podkop` (if there is no such file, remove `/etc/config/podkop`), then install podkop as its README says.

Problems and questions: [issues](https://github.com/podkop-net/podkop-experimental/issues).
