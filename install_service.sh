#!/bin/sh
sed "s#WorkingDirectory=.*#WorkingDirectory=$(pwd)#g" belaUI.service > /etc/systemd/system/belaUI.service &&
cp belaUI.socket /etc/systemd/system/
systemctl daemon-reload &&
systemctl restart belaUI &&
systemctl enable belaUI.socket
systemctl enable belaUI.service
cp 99-belaui-check-usb-devices.rules /etc/udev/rules.d/
