# mnemonic

* [Documentation](https://docs.rs/mnemonic)
* [crates.io](https://crates.io/crates/mnemonic)

This is a Rust port of the mnemonic encoder originally written in C by Oren
Tirosh and available from:

https://github.com/singpolyma/mnemonicode

These routines implement a method for encoding binary data into a sequence
of words which can be spoken over the phone, for example, and converted
back to data on the other side.

For more information, see:

http://web.archive.org/web/20101031205747/http://www.tothink.com/mnemonic/

## Example

```
let bytes = [101, 2, 240, 6, 108, 11, 20, 97];

let s = mnemonic::to_string(&bytes);
assert_eq!(s, "digital-apollo-aroma--rival-artist-rebel");

let mut decoded = Vec::<u8>::new();
mnemonic::decode(s, &mut decoded).unwrap();

assert_eq!(decoded, [101, 2, 240, 6, 108, 11, 20, 97]);
```
