# Writeup "Backup - Alice" (CRYPTO)

## Scenario

We have backup of Alice's home directory :

```
.
├── .ssh
│   └─── authorized_keys
├── .bash_logout
├── .bashrc
├── .profile
├── .flag.zip
└── .get_flag.sh
```

Inspect get_flag.sh:
```bash
#!/bin/sh
unzip -p -P$(cat ../password.alice) flag.zip
```

Flag is zipped with a password, too lazy to bruteforce it...

Inspect /.ssh/authorized_keys:
```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDv9fYADdQjY7ETSi+5ODxXmO2cKJRu4zL7s4yGHLMXVykw3P7PkPOYJ18Q0QZ2mt6hacE1Zw12UmibgjENV4GPR0GR+/N/NZ8t0Vti0hV+Rj3OQij0/W4RM+phTSmnA9Kz4j24ZMNnQAMl7MaOSjHRN+1TE4rETTBMpyKylYu01aGbLbzBBCcW+YeZLhAyYF1FoLyXjSEx6ucDFNE+ud8IrQWts4d50tWFHficRzulfsluo/D1RItasDDx6rtZUSAqWmLWw/XuTmvE4gkU1HsGi9jMnFrAV4sy/s+0jWy+GH/8X7Q1bgfxmX9HfGW3qnO/Kc5eFqX6i9RxnGbC/Yzx alice@work
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDlPRSh8cN2qd+lAVSf3tQnGy7gSmRiH9k2T3p0tVXD33SCiJaMmfqeIfQNe9sVKXi1E1J4rJ09Bv0Vht8Ti8yUY5B+wOh0JKGIPYMxClROo4a42pv4iDOECfZ77T6pHm5lDoAK5KDXvKy119TtXpl26/1+FYwr87kMjU/ZujAHQDMkx1JGUrQfipYMqV8Sm0ufyvTitP9NWV3fXNt83IAOheYbbI4lYkV/NqUbdW0FtBZiUuE9EZiM0ATLDYN5GIWE5jOCkUP5QBB9/X4w+keHSpxsyNI7/g4sNfFybjdNf7Kx2GmEeIe+xrU3X2xPO1j/px2QMZe0PhhIkbSF/YxL alice@home
```

Found 2 RSA Public Keys!!

## Analyze

There are 2 RSA public keys, extract parameters with a python script:
```python
#!/usr/bin/python2

import sys
import base64
import struct

# get the second field from the public key file.
keydata = raw_input("Base64 Public Key:\n")
keydata = base64.b64decode(keydata)
parts = []
while keydata:
    # read the length of the data
    dlen = struct.unpack('>I', keydata[:4])[0]

    # read in <length> bytes
    data, keydata = keydata[4:dlen+4], keydata[4+dlen:]

    parts.append(data)

e_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[1]]))
n_val = eval('0x' + ''.join(['%02X' % struct.unpack('B', x)[0] for x in parts[2]]))

print "e="
print e_val

print "n="
print n_val
```

Results:

1st RSA Public Key:

```bash
$ ./p.py 
Base64 Public Key:
AAAAB3NzaC1yc2EAAAADAQABAAABAQDv9fYADdQjY7ETSi+5ODxXmO2cKJRu4zL7s4yGHLMXVykw3P7PkPOYJ18Q0QZ2mt6hacE1Zw12UmibgjENV4GPR0GR+/N/NZ8t0Vti0hV+Rj3OQij0/W4RM+phTSmnA9Kz4j24ZMNnQAMl7MaOSjHRN+1TE4rETTBMpyKylYu01aGbLbzBBCcW+YeZLhAyYF1FoLyXjSEx6ucDFNE+ud8IrQWts4d50tWFHficRzulfsluo/D1RItasDDx6rtZUSAqWmLWw/XuTmvE4gkU1HsGi9jMnFrAV4sy/s+0jWy+GH/8X7Q1bgfxmX9HfGW3qnO/Kc5eFqX6i9RxnGbC/Yzx
e=
65537
n=
30292242746036115971017608982999250727717453656432023769003750409813735934710819201974159210260826408436902577095993755936818096216019228802218008805095250945851943575117108739663821796010390678994297744383588214605732433507054131494086784354478249764431583863823040817137498841468964275285759264488873023055232915029362296237879621242004026789135861602389065223171670193449202825454456361675908992418334133239350991783676572498332103136958336603939895528286642315040568556524401592641941738753256750084061561270732457810477455643729432407190682410033927743753783287469005235658010914542487780332979133840894080158961
```

2nd RSA PublicKey:
```bash
$ ./p.py 
Base64 Public Key:
AAAAB3NzaC1yc2EAAAADAQABAAABAQDlPRSh8cN2qd+lAVSf3tQnGy7gSmRiH9k2T3p0tVXD33SCiJaMmfqeIfQNe9sVKXi1E1J4rJ09Bv0Vht8Ti8yUY5B+wOh0JKGIPYMxClROo4a42pv4iDOECfZ77T6pHm5lDoAK5KDXvKy119TtXpl26/1+FYwr87kMjU/ZujAHQDMkx1JGUrQfipYMqV8Sm0ufyvTitP9NWV3fXNt83IAOheYbbI4lYkV/NqUbdW0FtBZiUuE9EZiM0ATLDYN5GIWE5jOCkUP5QBB9/X4w+keHSpxsyNI7/g4sNfFybjdNf7Kx2GmEeIe+xrU3X2xPO1j/px2QMZe0PhhIkbSF/YxL
e=
65537
n=
28938691801738590006069983977764214650843494790483455891163386974553753039366793575399500592888800239157529900750083679424173560982678176854248282521343575778206629768377453051008952525524506340336580410386977882351825310392438566743192930344512748403120130603977017740437435741283242099791556820701165392657281203225778765299110741281565941506554552651531981629938373519006523766965115711626502599619617340962108377030931530131444210485402
```

Uhm there are 2 public keys for same user, maybe they are generate with same prime number...
```bash
$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from math import gcd
>>> n1 = 30292242746036115971017608982999250727717453656432023769003750409813735934710819201974159210260826408436902577095993755936818096216019228802218008805095250945851943575117108739663821796010390678994297744383588214605732433507054131494086784354478249764431583863823040817137498841468964275285759264488873023055232915029362296237879621242004026789135861602389065223171670193449202825454456361675908992418334133239350991783676572498332103136958336603939895528286642315040568556524401592641941738753256750084061561270732457810477455643729432407190682410033927743753783287469005235658010914542487780332979133840894080158961
>>> n2 = 28938691801738590006069983977764214650843494790483455891163386974553753039366793575399500592888800239157529900750083679424173560982678176854248282521343575778206629768377453051008952525524506340336580410386977882351825310392438566743192930344512748403120130603977017740437435741283242099791556820701165392657281203225778765299110741281565941506554552651531981629938373519006523766965115711626502599619617340962108377030931530131444210485402390362821508145113660839057137101420567067990940899994907078517540208039763497143748147370842436428216430228764770034995168387883342764314325625983365837741521286781612972674123
>>> p = gcd(n1,n2)
>>> p
171271932272901803774128505983365082675029542666691747200477582499432049482725221456365399113480297074384917169149347993114697250080329906810077468818479458173346323889305093008389190427501456666485586943618415784519402027225089556051642516053179825638237155560833886980519882958785597519492961451928936581189
```

## Common Prime Attack

Given 2 RSA public keys built on:

![N_1](https://render.githubusercontent.com/render/math?math=N%5F1%20%3D%20p%2Aq&mode=inline)

![N_2](https://render.githubusercontent.com/render/math?math=N%5F2%20%3D%20p%2Ar&mode=inline)

Sharing a common prime factor prime will break both keys.

Both related private keys can be recovered in this way:

### Recalculate prime numbers

Using inverse formula:

![q](https://render.githubusercontent.com/render/math?math=q%20%3D%20N%5F1%20%2F%20p&mode=inline)

![r](https://render.githubusercontent.com/render/math?math=r%20%3D%20N%5F2%20%2F%20p&mode=inline)

### Recalculate Euler's totient

Using Euler's totient formula:

![phi(n)](https://render.githubusercontent.com/render/math?math=%5Cphi%28n%29%20%3D%20%28p%2D1%29%2A%28q%2D1&mode=inline)

### Recalulate second prime numbers

We have all parameters to calculate d parameter and recover private keys:

![d](https://render.githubusercontent.com/render/math?math=d%20%3D%20e%5E%7B%2D1%7D%20mod%20%5Cphi%28n%29&mode=inline)

Knowning p,q,e,d,n is possible to recover private keys.

## Script

[generate_keys.py](/Midnightsun CTF 2021/Scripts/generate_keys.py)

```python
#!/usr/bin/python3
from math import gcd
from Crypto.PublicKey import RSA

n1 = 30292242746036115971017608982999250727717453656432023769003750409813735934710819201974159210260826408436902577095993755936818096216019228802218008805095250945851943575117108739663821796010390678994297744383588214605732433507054131494086784354478249764431583863823040817137498841468964275285759264488873023055232915029362296237879621242004026789135861602389065223171670193449202825454456361675908992418334133239350991783676572498332103136958336603939895528286642315040568556524401592641941738753256750084061561270732457810477455643729432407190682410033927743753783287469005235658010914542487780332979133840894080158961
n2 = 28938691801738590006069983977764214650843494790483455891163386974553753039366793575399500592888800239157529900750083679424173560982678176854248282521343575778206629768377453051008952525524506340336580410386977882351825310392438566743192930344512748403120130603977017740437435741283242099791556820701165392657281203225778765299110741281565941506554552651531981629938373519006523766965115711626502599619617340962108377030931530131444210485402390362821508145113660839057137101420567067990940899994907078517540208039763497143748147370842436428216430228764770034995168387883342764314325625983365837741521286781612972674123
e = 65537

# Get common prime factor
p = gcd(n1,n2)

# Resolve other prime factors
q = n1 // p
r = n2 // p

# Calculate euler's totient
phi = (p-1)*(q-1)

# Calulate private key parameter
d = pow(65537,-1,(phi))

# Build Private Key
private_key = RSA.construct((n1, e, d))

# Save it in PEM format
f = open('mykey1.pem','wb')
f.write(private_key.export_key('PEM'))
f.close()
```

### Run Script

```bash
$ python2 generatekeys.py
$ ssh -i mykey1.pem -p2222 alice@backup-01.play.midnightsunctf.se
midnight{factorization_for_the_Win}
```