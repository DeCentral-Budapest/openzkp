# OpenZKP
Secure implementation of zero-knowledge proofs


OpenZKP is an effort to make a truly bullet-proof and industry-ready library for using zero-knowledge proofs in open-source and commercial applications, without the fear that you get confused in the math and make a mistake, ruining your application's confidentiality. OpenZKP is easy to use and has a similar syntax to OpenSSL. In fact it uses OpenSSL wherever it can to ensure security.

## Algorithms supported
- Feige–Fiat–Shamir identification scheme
- Generalized Chaum-pedersen proof (ILMP)

More to come...

## Usage
```
./configure
make
make install
gcc my_source.c -lzkp -lcrypto -lm
```

## License Information
OpenZKP is licensed under the Apache2 license, this means you can do anything with it, even for commercial use but keep in mind if that you **modify** the code you must state so. Crypto is a sensitive topic and one shall be completely confident whether this library has any modifications that could possibly break security.

```
Copyright 2016-2017 Ábrahám Endre

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
