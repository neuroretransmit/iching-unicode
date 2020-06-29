# iching

`iching` is a program to encrypt/decrypt a secret using ngrams (monogram, digram,
[trigram](https://en.wikipedia.org/wiki/Bagua),
[hexagram](https://en.wikipedia.org/wiki/List_of_hexagrams_of_the_I_Ching)) from the
[I Ching](https://en.wikipedia.org/wiki/I_Ching). It has various options that act like rotors in the
[Enigma machine](https://en.wikipedia.org/wiki/Enigma_machine), where some rotors can be randomized instead of just
offset.

## Usage

```
usage: iching.py [-h] [-b BASE] [-sb [SHUFFLE_BASE]] [-e ENCRYPT] [-d DECRYPT] [-bk BASE_KEY] [-oh [OFFSET_HEXAGRAMS]] [-sh [SHUFFLE_HEXAGRAMS]] [-hk HEXAGRAM_KEY] [-g GRAMS]

Hide messages in I Ching hexagrams

optional arguments:
  -h, --help            show this help message and exit
  -b BASE, --base BASE  target base [16, 32, 64]
  -sb [SHUFFLE_BASE], --shuffle-base [SHUFFLE_BASE]
                        shuffle base charset order
  -e ENCRYPT, --encrypt ENCRYPT
                        encrypt message
  -d DECRYPT, --decrypt DECRYPT
                        decrypt message
  -bk BASE_KEY, --base-key BASE_KEY
                        base key for decryption
  -oh [OFFSET_HEXAGRAMS], --offset-hexagrams [OFFSET_HEXAGRAMS]
                        offset hexagram slice for base [16, 32]
  -sh [SHUFFLE_HEXAGRAMS], --shuffle-hexagrams [SHUFFLE_HEXAGRAMS]
                        shuffle hexagram order
  -hk HEXAGRAM_KEY, --hexagram-key HEXAGRAM_KEY
                        hexagram key for decryption
  -g GRAMS, --grams GRAMS
                        ngram style ['mono', 'di', 'tri', 'hex']
```

## Tips

### Preferred Security Settings

To maximize message security, use the following command line options `./iching.py -sb -sh -e 'message here'`. This
defaults to base64, shuffles the base index key and shuffles the intermediate hexagrams. You will have two 64 character
keys after encrypting. You may use any of the ngrams (`-g`) with these settings, just know your message will be 2, 3 or
6 times longer than using the default hexagrams. Doing so adds another level of obscurity.

### Ngram Type Deduction on Decrypt

The decrypt function deduces which ngrams you used, no need to pass the `-g` flag on decryption.

### File Redirection

This script can safely be used with file redirection since keys and offsets are printed to stderr and the
encrypted secret can remain in stdout.

```bash
$ python iching.py -sb -sh -e 'test' > test.txt
Base Key: zt+3dUFZig8RXjfeq0oxDySCWMvVulc2AQKYsk95mwbB17T/6h4ONpPnHaJrGILE
Hexagram Key: ䷚䷏䷾䷮䷕䷖䷼䷦䷡䷴䷙䷬䷑䷣䷷䷞䷩䷃䷛䷸䷠䷫䷯䷧䷄䷳䷈䷐䷭䷗䷻䷊䷌䷽䷰䷝䷜䷀䷟䷿䷺䷘䷲䷂䷱䷶䷤䷢䷥䷎䷪䷇䷓䷒䷉䷋䷨䷅䷍䷵䷔䷹䷆䷁
$ cat test.txt
䷁䷙䷲䷌䷁䷴
```

## Examples

### Encrypt/decrypt hexagrams without any shuffling

```bash
$ ./iching.py -e 'test'
䷝䷆䷕䷳䷝䷀
$ ./iching.py -d '䷝䷆䷕䷳䷝䷀'
test
```

### Encrypt/decrypt to different ngrams without any shuffling

**NOTE:** See tips above for omitting the `-g` flag on decryption, it is not necessary.

```bash
$ ./iching.py -g tri -e test
☲☲☷☵☶☲☶☶☲☲☰☰
$ ./iching.py -d ☲☲☷☵☶☲☶☶☲☲☰☰
test
$  ./iching.py -g di -e test
⚎⚌⚍⚏⚏⚎⚎⚍⚍⚎⚍⚏⚎⚌⚍⚌⚌⚌
$ ./iching.py -d ⚎⚌⚍⚏⚏⚎⚎⚍⚍⚎⚍⚏⚎⚌⚍⚌⚌⚌
test
./iching.py -g mono -e test
⚊⚋⚊⚊⚋⚊⚋⚋⚋⚋⚊⚋⚊⚋⚋⚊⚋⚊⚊⚋⚋⚊⚋⚋⚊⚋⚊⚊⚋⚊⚊⚊⚊⚊⚊⚊
./iching.py -d ⚊⚋⚊⚊⚋⚊⚋⚋⚋⚋⚊⚋⚊⚋⚋⚊⚋⚊⚊⚋⚋⚊⚋⚋⚊⚋⚊⚊⚋⚊⚊⚊⚊⚊⚊⚊
test
```

### Encrypt/decrypt hexagrams in a different base without any shuffling

```bash
$ ./iching.py -b32 -e 'test'
䷎䷑䷒䷗䷆䷝䷀
$ ./iching.py -b32 -d '䷎䷑䷒䷗䷆䷝䷀'
test
```

### Encrypt/decrypt hexagrams in base16/32 with offset hexagrams and without shuffling

```bash
$ ./iching.py -b32 -oh -e 'test'
Hexagram Offset: 9
䷗䷚䷛䷠䷏䷦䷉
$ ./iching.py -b32 -oh 9 -d '䷗䷚䷛䷠䷏䷦䷉'
test
```

### Encrypt/decrypt hexagrams with shuffled base key

```bash
$ ./iching.py -sb -e 'test'
Base64 Key: rOuy0aYGvnp9o7Q8qLH5i62XNRhCjDZklKewUS/1+4VTfIPcWgAbx3MtzEmFdsJB
䷏䷒䷐䷩䷏䷃
$ ./iching.py -bk 'rOuy0aYGvnp9o7Q8qLH5i62XNRhCjDZklKewUS/1+4VTfIPcWgAbx3MtzEmFdsJB' -d '䷏䷒䷐䷩䷏䷃'
test
```

### Encrypt/decrypt hexagrams in base16/32 with offset hexagrams and shuffled base key

```bash
$ ./iching.py -b32 -sb -oh -e 'test'
Base32 Key: RMWT7YSCF34EQPLX5OVH6DANZGK2JBIU
Hexagram Offset: 28
䷜䷲䷵䷩䷴䷨䷞
$ ./iching.py -b32 -bk 'RMWT7YSCF34EQPLX5OVH6DANZGK2JBIU' -oh 28 -d '䷜䷲䷵䷩䷴䷨䷞'
test
```

### Encrypt/decrypt hexagrams in base16/32 with offset hexagrams and shuffled base/hexagram key

```bash
$ ./iching.py -b32 -sb -oh -sh -e 'test'
Base32 Key: AYJWX26DCS3BFUNZPGL4R7MVKIE5QTHO
Hexagram Key: ䷏䷇䷊䷕䷛䷉䷞䷗䷐䷖䷙䷅䷈䷌䷎䷍䷑䷢䷆䷝䷚䷜䷡䷘䷔䷠䷟䷒䷣䷄䷓䷋
䷜䷌䷊䷟䷚䷙䷏
$ ./iching.py -b32 -bk AYJWX26DCS3BFUNZPGL4R7MVKIE5QTHO \
    -hk ䷏䷇䷊䷕䷛䷉䷞䷗䷐䷖䷙䷅䷈䷌䷎䷍䷑䷢䷆䷝䷚䷜䷡䷘䷔䷠䷟䷒䷣䷄䷓䷋ \
    -d ䷜䷌䷊䷟䷚䷙䷏
test
```

### Encrypt/decrypt hexagrams in base64 with shuffled base/hexagram key

```bash
$ ./iching.py -sb -sh -e 'test'
Base64 Key: HSGtm3plsyX4+c6UwqO5vYaA8/2QMLhejCuNKgJRP19VozkDxEdTbFfrIZiWn70B
Hexagram Key: ䷹䷴䷩䷡䷐䷶䷗䷭䷄䷯䷛䷼䷟䷂䷠䷳䷒䷵䷽䷁䷙䷰䷾䷆䷔䷫䷿䷺䷌䷱䷥䷻䷚䷤䷊䷘䷃䷜䷇䷪䷑䷲䷝䷍䷅䷕䷢䷷䷏䷧䷞䷨䷈䷸䷀䷖䷬䷣䷎䷮䷋䷉䷓䷦
䷯䷤䷖䷡䷯䷛
$ ./iching.py -bk HSGtm3plsyX4+c6UwqO5vYaA8/2QMLhejCuNKgJRP19VozkDxEdTbFfrIZiWn70B \
    -hk ䷹䷴䷩䷡䷐䷶䷗䷭䷄䷯䷛䷼䷟䷂䷠䷳䷒䷵䷽䷁䷙䷰䷾䷆䷔䷫䷿䷺䷌䷱䷥䷻䷚䷤䷊䷘䷃䷜䷇䷪䷑䷲䷝䷍䷅䷕䷢䷷䷏䷧䷞䷨䷈䷸䷀䷖䷬䷣䷎䷮䷋䷉䷓䷦ \
    -d ䷯䷤䷖䷡䷯䷛
test
```

## Running tests

`./tests.py`
