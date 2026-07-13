#!/bin/sh

if [ "$(id -u)" != "0" ]; then
    exec sudo "$0" "$@"
fi

install -o +0 -g +0 -m 755 ./one_time_unlock_and_reboot.sh /usr/bin/one_time_unlock_and_reboot
install -o +0 -g +0 -m 755 ./build_hook.sh /etc/initcpio/install/one_time_unlock
install -o +0 -g +0 -m 755 ./runtime_hook.sh /etc/initcpio/hooks/one_time_unlock
