# Writeup "Backup - Bob" (CRYPTO)

# Contents

- [Scenario](#scenario)
- [Analysis](#analysis)
- [Direct Factorization](#direct-factorization)
- [Script](#script)

## Scenario

We have backup of Bob's home directory :

```
.
├── .ssh
│   └─── authorized_keys
├── .bash_logout
├── .bashrc
├── .profile
├── .flag.enc
└── .get_flag.sh
```

Inspect get_flag.sh:
```bash
#!/bin/sh
openssl enc -aes-256-cbc -d -k $(cat ../password.bob) -in flag.enc 2>/dev/null
```

AES-256 bruteforce ? NAAAAAH!

Inspect authorized_keys:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAiNqJM3LzsulIQSh/OVU4Nbtfvnn6PictEw7rKCmAHgufbeBQWcM5PeZurgy8j1fhMJiyUkXkmwnZLCDDMTy9qwU3uCUSdYBkAxLUt8JE8VBdtDkAv5KNX4U6Mc+PP231/wddc1//0/XItvFL8vmr9nUadmPG6vyr+fahaZ+Rod2Ipz8x0LatSHNE0S4VRDW2FcJOvgM9dLyOF6ivdCKmbx53xDrr1B8AjoJHnCGyygLunRSDOK3USVdM6mQumQCjjVWMElJZshxrKFfUtxDqrIePLdVHI7IxPINYpPxvTw+giIYaN1/8YQ/YbUFMQJZLlcNsVtS7ucfBkVeSh7gTMYdRw==
```

Found a RSA Public Key!

## Analysis

Extract public key parameters with a python script:
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

Result:
```bash
$ ./p.py 
Base64 Public Key:
AAAAB3NzaC1yc2EAAAADAQABAAABAiNqJM3LzsulIQSh/OVU4Nbtfvnn6PictEw7rKCmAHgufbeBQWcM5PeZurgy8j1fhMJiyUkXkmwnZLCDDMTy9qwU3uCUSdYBkAxLUt8JE8VBdtDkAv5KNX4U6Mc+PP231/wddc1//0/XItvFL8vmr9nUadmPG6vyr+fahaZ+Rod2Ipz8x0LatSHNE0S4VRDW2FcJOvgM9dLyOF6ivdCKmbx53xDrr1B8AjoJHnCGyygLunRSDOK3USVdM6mQumQCjjVWMElJZshxrKFfUtxDqrIePLdVHI7IxPINYpPxvTw+giIYaN1/8YQ/YbUFMQJZLlcNsVtS7ucfBkVeSh7gTMYdRw==
e=
65537
n=
292990623103335493083913779240227114014904398616038776886875167758623613267713719485674604784729195181038351832618761824038504140656599226185121583057564640306785410343719022605570022010005365168476355940663606943398746699884693312099702534701527459939206645436661317995669108935090673904917668084888759984068936279043561859031475316147764516900077276002733154419678141190215602495515119640962345701087676290867864254791059984691165085786925183275218310949675831467166068472807231810975997996854523424726065091238482206852784278991075956030040050699499746167768437515319815674181113042108365139058834101801220867518504263
```

Search n on factordb:

(10007 * 2927856731...09)(http://factordb.com/index.php?id=1100000002547903635)

n has been factorized, private key can be recovered

## Direct Factorization

e, p, q and n are known, we need to calculate d:

### Recalculate Euler's totient

Using Euler's totient formula:

![phi(n)](https://render.githubusercontent.com/render/math?math=%5Cphi%28n%29%20%3D%20%28p%2D1%29%2A%28q%2D1%29&mode=inline)

### Recalulate d

![d](https://render.githubusercontent.com/render/math?math=d%20%3D%20e%5E%7B%2D1%7D%20%20mod%20%5Cphi%28n%29&mode=inline)

## Script
```
#!/usr/bin/python3
from Crypto.PublicKey import RSA
from factordb.factordb import FactorDB

n = 292990623103335493083913779240227114014904398616038776886875167758623613267713719485674604784729195181038351832618761824038504140656599226185121583057564640306785410343719022605570022010005365168476355940663606943398746699884693312099702534701527459939206645436661317995669108935090673904917668084888759984068936279043561859031475316147764516900077276002733154419678141190215602495515119640962345701087676290867864254791059984691165085786925183275218310949675831467166068472807231810975997996854523424726065091238482206852784278991075956030040050699499746167768437515319815674181113042108365139058834101801220867518504263
e = 65537

# Solved by factordb
p = 10007
q = 29278567313214299298882160411734497253413050726095610761154708479926412837784922502815489635727909981117053245989683404021035689083301611490468830124669195593762906999472271670387730789447922970768097925518497745917732257408283532737054315449338209247447451327736716098298102221953699800631324881072125510549508971624219232440439224157865945528138030978588303629427215068473628709454893538619201129318244857686405941320181871159304995082135023810854233131775340408430705353533249906163285499835567445260923862420154112806314008093442186072753077915409188185047310634088119883499661541132044083047749985190488744630609

# Calculate euler's totient
phi = (p-1)*(q-1)

# Calulate private key parameter
d = pow(65537,-1,(phi))

# Build Private Key
private_key = RSA.construct((n, e, d))

# Save it in PEM format
f = open('mykeyb.pem','wb')
f.write(private_key.export_key('PEM'))
f.close()
```

### Run Script

```bash
$ python2 generatekeys.py
$ ssh -i mykeyb.pem -p2222 bob@backup-01.play.midnightsunctf.se
midnight{Turn_electricity_t0_h347}
```
