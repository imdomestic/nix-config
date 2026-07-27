# Trusted SSH public keys, shared by the normal sshd (via
# /etc/ssh/authorized_keys.d/master) and by tank's initrd sshd, which cannot
# read that file because it lives on the root filesystem it is trying to mount.
[
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINR7+B5jirLm5+cXrKabb0hrvq1OFxX6jCzKi/Sb4rkj ysh2291939848@outlook.com"
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ/MFKoIlH1i0YDAnIoHQKmKEKFGcKa1V4gET/bYifcd ysh2291939848@outlook.com"
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG290WBMVGWxpye7MliOTbiCZAd3mbi/Q9sFkBLE2Vno ysh2291939848@outlook.com"
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILUdWAJA+GYaOtVHVkrvrEpwGpK//0hYdAYjYq/rzvtn ysh2291939848@outlook.com" # m1elite
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBY3nWjTRRfjPPtriUf6Ot5Qg83/3u2SA6ih8x5jrLYX ysh2291939848@outlook.com" # hackintosh
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAVka3wlxrH8v1fFxiTGxd8cnoAtbLyWDrb5xibOtDg4 linwhite@linwhite.top"
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII6G+ioInToTcwGDI+Tnoq5/X/GpmEucCilJH6pkZOdJ 1823215739@qq.com" # fendada
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAhXv+E5zF8pdF9SqxGMc21iAZYOuxPgP5rEx1DbtAsK 3526452465@qq.com" # kenneth
]
