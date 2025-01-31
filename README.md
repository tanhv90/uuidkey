```sh
                         _   _  _   _  ___ ____     _  __          
                        | | | || | | ||_ _|  _ \   | |/ /___ _   _ 
                        | | | || | | | | || | | |  | ' // _ \ | | |
                        | |_| || |_| | | || |_| |  | . \  __/ |_| |
                         \___/  \___/ |___|____/   |_|\_\___|\__, |
                                                             |___/ 
```

[![codecov](https://codecov.io/gh/tanhv90/uuidkey/graph/badge.svg?token=MMCEEW697S)](https://codecov.io/gh/tanhv90/uuidkey)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/tanhv90/uuidkey/master/LICENSE)

A Node.js implementation of the [agentstation/uuidkey](https://github.com/agentstation/uuidkey) library, originally written in Go.

## Overview

The `uuidkey` package generates secure, readable API keys by encoding UUIDs using Base32-Crockford with additional security features.

You can use the `uuidkey` package to generate API keys for your application using the `newAPIKey` function (recommended to guarantee at least 128 bits of entropy and follow the GitHub Secret Scanning format) or the `encode` function (to generate just a `Key` type).

## API Key Format

```
AGNTSTNP_38QARV01ET0G6Z2CJD9VA2ZZAR0XJJLSO7WBNWY3F_A1B2C3D8
└─────┘ └──────────────────────────┘└────────────┘ └──────┘
Prefix        Key (crock32 UUID)        Entropy      Checksum
```

### Components
1. **Prefix** - Company/application identifier (e.g., "AGNTSTNP")
2. **Key** - Base32-Crockford encoded UUID
3. **Entropy** - Additional random data (128, 160, or 256 bits)
4. **Checksum** - CRC32 checksum (8 characters) for validation

### Security Features
1. **Secret Scanning** - Formatted for GitHub Secret Scanning detection
2. **Validation** - CRC32 checksum for error detection and validation
3. **Entropy Options** - Configurable entropy levels that ensure UUIDv7 security (128, 160, or 256 bits)

## Installation

To install the `uuidkey` package, use the following command:

```sh
npm i uuidkey
```

## Usage

```typescript
import { newAPIKey, parse, Options } from 'uuidkey';

let apiKey = newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601d');
console.log(apiKey)
/*
APIKey {
  prefix: 'MYPREFIX',
  key: Key { value: '38QARV01ET0G6Z2CJD9VA2ZZAR0X' },
  entropy: 'SMJP4AMEEWHGZDCGDDBBF',
  checksum: '86887EAC'
}
*/
console.log(apiKey.toString())
// MYPREFIX_38QARV01ET0G6Z2CJD9VA2ZZAR0XSMJP4AMEEWHGZDCGDDBBF_86887EAC

apiKey = newAPIKey('MYPREFIX', 'd1756360-5da0-40df-9926-a76abff5601d', Options.With128BitEntropy);
console.log(apiKey)
/*
APIKey {
  prefix: 'MYPREFIX',
  key: Key { value: '38QARV01ET0G6Z2CJD9VA2ZZAR0X' },
  entropy: '1R3QJNHCBA9RCX',
  checksum: 'B51D4BAB'
}
*/

apiKey = parse('MYPREFIX_38QARV01ET0G6Z2CJD9VA2ZZAR0XSMJP4AMEEWHGZDCGDDBBF_86887EAC');
console.log(apiKey)
/*
APIKey {
  prefix: 'MYPREFIX',
  key: Key { value: '38QARV01ET0G6Z2CJD9VA2ZZAR0X' },
  entropy: 'SMJP4AMEEWHGZDCGDDBBF',
  checksum: '86887EAC'
}
*/
```