# iching

`iching` is a program to encrypt a secret using hexagrams from the [I Ching](https://en.wikipedia.org/wiki/I_Ching).
It has various options that act like rotors in the [Enigma machine](https://en.wikipedia.org/wiki/Enigma_machine),
where rotors can be randomized instead of just offset.

## Usage

```
usage: iching.py [-h] [-b BASE] [-sb [SHUFFLE_BASE]] [-e ENCRYPT] [-d DECRYPT] [-bk BASE_KEY] [-oh [OFFSET_HEXAGRAMS]] [-sh [SHUFFLE_HEXAGRAMS]] [-hk HEXAGRAM_KEY]

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
```

## Tips

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

Simply mapping the hexagrams to base64 without any randomization or offset:

```bash
$ # Encoding
$ ./iching.py -e 'test'
䷝䷆䷕䷳䷝䷀
$ # Decoding
$ ./iching.py -d '䷝䷆䷕䷳䷝䷀'
test
```

Using a different base numbering system:

```bash
$ ./iching.py -b32 -e 'test'
䷎䷑䷒䷗䷆䷝䷀
$ ./iching.py -b32 -d '䷎䷑䷒䷗䷆䷝䷀'
test
```

Shifting the slice of hexagrams for bases lower than 64:

```bash
$ ./iching.py -b32 -oh -e 'test'
Hexagram Offset: 9
䷗䷚䷛䷠䷏䷦䷉
$ ./iching.py -b32 -oh 9 -d '䷗䷚䷛䷠䷏䷦䷉'
test
```

Shuffling the base index key:

```bash
$ ./iching.py -s -e 'test'
Base Key: rOuy0aYGvnp9o7Q8qLH5i62XNRhCjDZklKewUS/1+4VTfIPcWgAbx3MtzEmFdsJB
䷏䷒䷐䷩䷏䷃
$ ./iching.py -bk 'rOuy0aYGvnp9o7Q8qLH5i62XNRhCjDZklKewUS/1+4VTfIPcWgAbx3MtzEmFdsJB' -d '䷏䷒䷐䷩䷏䷃'
test
```

Shuffling both the index key and offsetting hexagrams for bases lower than 64:

```bash
$ ./iching.py -b32 -s -oh -e 'test'
Base Key: RMWT7YSCF34EQPLX5OVH6DANZGK2JBIU
Hexagram Offset: 28
䷜䷲䷵䷩䷴䷨䷞
$ ./iching.py -b32 -bk 'RMWT7YSCF34EQPLX5OVH6DANZGK2JBIU' -oh 28 -d '䷜䷲䷵䷩䷴䷨䷞'
test
```

Shuffling both the index key and offsetting/shuffling hexagrams for bases lower than 64:

```bash
$ ./iching.py -b32 -sb -oh -sh -e 'test'
Base Key: AYJWX26DCS3BFUNZPGL4R7MVKIE5QTHO
Hexagram Key: ䷏䷇䷊䷕䷛䷉䷞䷗䷐䷖䷙䷅䷈䷌䷎䷍䷑䷢䷆䷝䷚䷜䷡䷘䷔䷠䷟䷒䷣䷄䷓䷋
䷜䷌䷊䷟䷚䷙䷏
$ ./iching.py -b32 -bk AYJWX26DCS3BFUNZPGL4R7MVKIE5QTHO \
    -hk ䷏䷇䷊䷕䷛䷉䷞䷗䷐䷖䷙䷅䷈䷌䷎䷍䷑䷢䷆䷝䷚䷜䷡䷘䷔䷠䷟䷒䷣䷄䷓䷋ \
    -d ䷜䷌䷊䷟䷚䷙䷏
test
```

Shuffling both the index key hexagrams for base 64:

```bash
$ ./iching.py -sb -sh -e 'test'
Base Key: HSGtm3plsyX4+c6UwqO5vYaA8/2QMLhejCuNKgJRP19VozkDxEdTbFfrIZiWn70B
Hexagram Key: ䷹䷴䷩䷡䷐䷶䷗䷭䷄䷯䷛䷼䷟䷂䷠䷳䷒䷵䷽䷁䷙䷰䷾䷆䷔䷫䷿䷺䷌䷱䷥䷻䷚䷤䷊䷘䷃䷜䷇䷪䷑䷲䷝䷍䷅䷕䷢䷷䷏䷧䷞䷨䷈䷸䷀䷖䷬䷣䷎䷮䷋䷉䷓䷦
䷯䷤䷖䷡䷯䷛
$ ./iching.py -bk HSGtm3plsyX4+c6UwqO5vYaA8/2QMLhejCuNKgJRP19VozkDxEdTbFfrIZiWn70B \
    -hk ䷹䷴䷩䷡䷐䷶䷗䷭䷄䷯䷛䷼䷟䷂䷠䷳䷒䷵䷽䷁䷙䷰䷾䷆䷔䷫䷿䷺䷌䷱䷥䷻䷚䷤䷊䷘䷃䷜䷇䷪䷑䷲䷝䷍䷅䷕䷢䷷䷏䷧䷞䷨䷈䷸䷀䷖䷬䷣䷎䷮䷋䷉䷓䷦ \
    -d ䷯䷤䷖䷡䷯䷛
test
```

## Running tests

`./tests.py`
