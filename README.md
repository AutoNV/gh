<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0ea5e9,100:6366f1&height=200&section=header&text=NEXUSDEV&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=VPN%20REST%20API%20Documentation&descAlignY=60&descColor=ffffff&descSize=20" width="100%"/>

<br/>

[![Telegram](https://img.shields.io/badge/Order%20%2F%20Sewa-@nexusweb__dev-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/nexusweb_dev)
[![Developer](https://img.shields.io/badge/Developer-Nexusdev-6366f1?style=for-the-badge&logo=github&logoColor=white)](https://t.me/nexusweb_dev)
[![OS](https://img.shields.io/badge/Ubuntu-20.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![License](https://img.shields.io/badge/License-Proprietary-dc2626?style=for-the-badge&logo=shield&logoColor=white)](https://t.me/nexusweb_dev)

<br/>

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=for-the-badge&logo=nginx&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 🌐 Base URL

```
https://yourdomain.com/api/
```

> Semua request wajib menyertakan parameter `auth` berisi API Key.

---

## 🔐 SSH

### Trial SSH
```
GET /api/trial-ssh
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `minutes` | integer | ❌ | Durasi trial dalam menit (default: 60) |

---

### Buat Akun SSH
```
GET /api/create-ssh
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun SSH |
| `password` | string | ✅ | Password akun SSH |
| `exp` | integer | ✅ | Masa aktif dalam hari |
| `quota` | integer | ❌ | Kuota bandwidth (GB), 0 = unlimited |
| `limitip` | integer | ❌ | Maks login bersamaan, 0 = unlimited |

---

### Hapus Akun SSH
```
GET /api/delssh
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun SSH yang dihapus |

---

### Renew Akun SSH
```
GET /api/rensh
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun SSH |
| `exp` | integer | ✅ | Perpanjangan masa aktif dalam hari |

---

## 📡 VMess

### Trial VMess
```
GET /api/trial-vmess
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `minutes` | integer | ❌ | Durasi trial dalam menit (default: 60) |

---

### Buat Akun VMess
```
GET /api/create-vmess
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun VMess |
| `quota` | integer | ✅ | Kuota bandwidth (GB), 0 = unlimited |
| `limitip` | integer | ✅ | Maks login bersamaan, 0 = unlimited |
| `exp` | integer | ✅ | Masa aktif dalam hari |

---

### Hapus Akun VMess
```
GET /api/delws
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun VMess yang dihapus |

---

### Renew Akun VMess
```
GET /api/renws
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun VMess |
| `exp` | integer | ✅ | Perpanjangan masa aktif dalam hari |

---

## 🔷 VLess

### Trial VLess
```
GET /api/trial-vless
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `minutes` | integer | ❌ | Durasi trial dalam menit (default: 60) |

---

### Buat Akun VLess
```
GET /api/create-vless
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun VLess |
| `quota` | integer | ✅ | Kuota bandwidth (GB), 0 = unlimited |
| `limitip` | integer | ✅ | Maks login bersamaan, 0 = unlimited |
| `exp` | integer | ✅ | Masa aktif dalam hari |

---

### Hapus Akun VLess
```
GET /api/delvl
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun VLess yang dihapus |

---

### Renew Akun VLess
```
GET /api/renvl
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun VLess |
| `exp` | integer | ✅ | Perpanjangan masa aktif dalam hari |

---

## 🛡️ Trojan

### Trial Trojan
```
GET /api/trial-trojan
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `minutes` | integer | ❌ | Durasi trial dalam menit (default: 60) |

---

### Buat Akun Trojan
```
GET /api/create-trojan
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun Trojan |
| `quota` | integer | ✅ | Kuota bandwidth (GB), 0 = unlimited |
| `limitip` | integer | ✅ | Maks login bersamaan, 0 = unlimited |
| `exp` | integer | ✅ | Masa aktif dalam hari |

---

### Hapus Akun Trojan
```
GET /api/deltr
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun Trojan yang dihapus |

---

### Renew Akun Trojan
```
GET /api/rentr
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `user` | string | ✅ | Username akun Trojan |
| `exp` | integer | ✅ | Perpanjangan masa aktif dalam hari |

---

## 🌀 ZIVPN UDP

### Trial ZIVPN
```
GET /api/trial-zivpn
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `minutes` | integer | ❌ | Durasi trial dalam menit (default: 60) |

---

### Buat Akun ZIVPN
```
GET /api/create-zivpn
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `password` | string | ✅ | Password akun ZIVPN |
| `exp` | integer | ✅ | Masa aktif dalam hari |

---

### Hapus Akun ZIVPN
```
GET /api/delzv
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `password` | string | ✅ | Password akun ZIVPN yang dihapus |

---

### Renew Akun ZIVPN
```
GET /api/renzv
```
| Parameter | Tipe | Wajib | Keterangan |
|-----------|------|-------|------------|
| `auth` | string | ✅ | API Key autentikasi |
| `password` | string | ✅ | Password akun ZIVPN |
| `exp` | integer | ✅ | Perpanjangan masa aktif dalam hari |

---

## 📋 Terms of Service

```
❌  NO SPAM
❌  NO DDOS / FLOODING
❌  NO HACKING / CARDING
❌  NO TORRENT
❌  NO MULTI LOGIN
❌  NO RESELL WITHOUT PERMISSION
```

> ⚠️ Pelanggaran akan mengakibatkan penghentian layanan secara permanen tanpa pengembalian dana.

---

<div align="center">

## 🛒 Order / Sewa

[![Telegram Order](https://img.shields.io/badge/💬%20Telegram-@nexusweb__dev-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white&labelColor=1a1a2e)](https://t.me/nexusweb_dev)

| | |
|:---:|:---|
| **Developer** | Nexusdev |
| **Telegram** | [@nexusweb_dev](https://t.me/nexusweb_dev) |
| **Stack** | Bash · JavaScript · Node.js · Python · Nginx |

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:6366f1,100:0ea5e9&height=100&section=footer" width="100%"/>

**⚡ NEXUSDEV — Built with ❤️ by [@nexusweb_dev](https://t.me/nexusweb_dev)**

</div>
