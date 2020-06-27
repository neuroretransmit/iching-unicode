# iching

`iching` is a program to encrypt a secret using hexagrams from the [I Ching](https://en.wikipedia.org/wiki/I_Ching). 
It has various options that act like rotors in the [Enigma machine](https://en.wikipedia.org/wiki/Enigma_machine), 
where rotors can be randomized instead of just offset.

## Usage

```
usage: iching.py [-h] [-b BASE] [-s [SHUFFLE]] [-e ENCRYPT] [-d DECRYPT] [-k KEY] [-oh [OFFSET_HEXAGRAMS]]

Hide messages in I Ching hexagrams

optional arguments:
  -h, --help            show this help message and exit
  -b BASE, --base BASE  target base [16, 32, 64]
  -s [SHUFFLE], --shuffle [SHUFFLE]
                        shuffle base index table
  -e ENCRYPT, --encrypt ENCRYPT
                        encrypt message
  -d DECRYPT, --decrypt DECRYPT
                        decrypt message
  -k KEY, --key KEY     key for decryption
  -oh [OFFSET_HEXAGRAMS], --offset-hexagrams [OFFSET_HEXAGRAMS]
                        offset hexagram slice for base [16, 32]
```

## Running tests

`./tests.py`

## Tips

This script can safely be used with file redirection since keys and offsets are printed to stderr and the
encrypted secret can remain in stdout.

```
$ python iching.py -b32 -s -oh -e 'test' > test.txt
Key: 3X6NYWVBKJSMQIRZAF7GOPHTC25D4LEU
Hexagram Offset: 18
$ cat test.txt 
䷱䷦䷚䷙䷩䷫䷞
```

## Examples

Simply mapping the hexagrams to base64 without any randomization or offset:

```bash
$ # Encoding
$ ./iching.py -e 'test'
䷝䷆䷕䷳䷝䷀
$ # Decoding
$ ./iching.py -d '䷝䷆䷕䷳䷝䷀'`
test
```

Using a different base numbering system:

```
$ ./iching.py -b32 -e 'test'
䷎䷑䷒䷗䷆䷝䷀
$ ./iching.py -b32 -d '䷎䷑䷒䷗䷆䷝䷀'
test
```

Shifting the slice of hexagrams for bases lower than 64:

```
$ ./iching.py -b32 -oh -e 'test'
Hexagram Offset: 9
䷗䷚䷛䷠䷏䷦䷉
$ ./iching.py -b32 -oh 9 -d '䷗䷚䷛䷠䷏䷦䷉'
test
````

Shuffling the base index key:

```
$ ./iching.py -s -e 'test'
Key: rOuy0aYGvnp9o7Q8qLH5i62XNRhCjDZklKewUS/1+4VTfIPcWgAbx3MtzEmFdsJB
䷏䷒䷐䷩䷏䷃
$ ./iching.py -k 'rOuy0aYGvnp9o7Q8qLH5i62XNRhCjDZklKewUS/1+4VTfIPcWgAbx3MtzEmFdsJB' -d '䷏䷒䷐䷩䷏䷃'
test
```

Shuffling both the index key and offsetting hexagrams for bases lower than 64:

```
$ ./iching.py -b32 -s -oh -e 'test'
Key: RMWT7YSCF34EQPLX5OVH6DANZGK2JBIU
Hexagram Offset: 28
䷜䷲䷵䷩䷴䷨䷞
$ ./iching.py -b32 -k 'RMWT7YSCF34EQPLX5OVH6DANZGK2JBIU' -oh 28 -d '䷜䷲䷵䷩䷴䷨䷞'
test
```
