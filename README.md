## sHKDF

### About

**Highly experimental** backdoor-resistant salted-HMAC-based Key Derivation function.

An HKDF implementation that is resistant to backdoors in the hashing primitives
compression function. You can read more about this implementation [here](2018/08/27/securing-hkdf-against-backdoors.html).



Based on the work of Marc Fischlin, Christian Janson and Sogol Mazaheri in
["Backdoored Hash Functions: Immunizing HMAC and HKDF"](https://eprint.iacr.org/2018/362.pdf) and Shai Halevi and Hugo Krawczyk in ["Strengthening Digital Signatures via Randomized Hashing"](https://www.iacr.org/archive/crypto2006/41170039/41170039.pdf).

### License
sHKDF is licensed under the MIT license. See the `LICENSE` file for more information.
