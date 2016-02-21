#!/bin/bash
source ~/.bash_profile
if [ "$LANG" = 'ja_JP.UTF-8' ]; then
export XMODIFIERS="@im=ibus"
export XMODIFIER="@im=ibus"
export GTK_IM_MODULE=ibus
export QT_IM_MODULE=ibus
export DefaultIMModule=ibus
ibus-daemon -drx
fi
exec xfce4-session
