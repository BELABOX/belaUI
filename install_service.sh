#!/bin/sh
sed "s#WorkingDirectory=.*#WorkingDirectory=$(pwd)#g" belaUI.service > /etc/systemd/system/belaUI.service &&
systemctl daemon-reload &&
systemctl restart belaUI &&
systemctl enable belaUI
cp 99-belaui-check-usb-devices.rules /etc/udev/rules.d/
