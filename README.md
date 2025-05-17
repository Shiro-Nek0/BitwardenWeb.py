# BitwardenWeb.py

Requires [BitwardenDecrypt.py](https://github.com/GurpreetKang/BitwardenDecrypt) in the same folder as main.py for it to work.

Minimal code to gather **encrypted** data.json from Bitwarden instance (BitwardenDecrypt.py not required):
```python
from BWConnect import ConnectionHandler
import json #not required

bwc = ConnectionHandler("https://VAULTWARDEN_URL", "EMAIL", "PASSWORD","TWO_FACTOR_AUTH_SECRET")

with open("vaultData.json", 'w', encoding='utf8') as file:
    json.dump(bwc.vaultData, file, ensure_ascii=False, indent=4)
```