# iching

`iching` is a program to encrypt/decrypt a secret using ngrams (monogram, digram,
[trigram](https://en.wikipedia.org/wiki/Bagua),
[hexagram](https://en.wikipedia.org/wiki/List_of_hexagrams_of_the_I_Ching)) from the
[I Ching](https://en.wikipedia.org/wiki/I_Ching).

## FAQ

### *Why?*

1. You can't backdoor this.
2. Invulnerable to cribbing.
3. Invulnerable to genetic algorithms/hill-climbing.
4. Computationally inexpensive to encrypt/decrypt.
5. No heavy math skills required to understand.
6. Brute-force takes eons.

#### *Why the I Ching?*

It conveniently has 64 hexagrams, it was between that and codons. It also has the bonus feature of consisting of
monograms, digrams, trigrams, and hexagrams, which can all be related to each other and change the ciphertext.

### *Isn't this security through obscurity?*

Actually, no. If this was simply a base conversion I'd agree with you, however - this is character-level encryption on
the intermediate representation of the message in baseN via shuffling the mapping of the base64 charset to I Ching
hexagrams and leaks no entropy.

### *Okay, but certainly there must be an efficient attack... right?*

Like attacking primes? Try attacking an ungodly big number/algorithm that doesn't care about a few special primes.

Let's think about this...

1. You are essentially trying to attack a massive number.
2. You must know the secret's text encoding or lack thereof.
3. You have no means of checking whether the text (or raw bytes) are valid without decoding from its base numbering
system. Your key search space is 64<sup>64</sup> in base64 (if the encrypted message is long enough to include 64 unique
characters).
4. Even if your encrypted message is, say, 10 characters...
    * t = time to compute one permutation, lets say 0.045045440404036347 seconds
    * 10<sup>64</sup> * t = 4.50454404×10<sup>62</sup> seconds
    * Full run time: 5.2135926389×10<sup>57</sup> Days
5. Genetic algorithms/hill-climbing will not be able to attack this, I'm 99% positive this is not feasible. Since this
leaks no entropy, you can limit the range of chunk-sizes to the character encoding (if you know it), however it will
create any characters you want in that set and give you valid decodes. If anyone has a valid fitness function for attack
I'd love to see it and subvert it.
6. I have included a brute-force attack in the source for you. Hope you have an army and rewrite the code to distribute
it amongst nodes. Good luck.

## Usage

```
usage: iching.py [-h] [-e ENCRYPT] [-g NGRAMS] [-sb [SHUFFLE_BASE]] [-sh [SHUFFLE_HEXAGRAMS]] [-d DECRYPT] [-bk BASE_KEY] [-hk HEXAGRAM_KEY] [-b BASE] [-oh [OFFSET_HEXAGRAMS]]

Hide messages in I Ching ngrams

optional arguments:
  -h, --help            show this help message and exit
  -e ENCRYPT, --encrypt ENCRYPT
                        encrypt message
  -g NGRAMS, --ngrams NGRAMS
                        ngram style {'mono', 'di', 'tri', 'hex'}
  -sb [SHUFFLE_BASE], --shuffle-base [SHUFFLE_BASE]
                        shuffle base charset order
  -sh [SHUFFLE_HEXAGRAMS], --shuffle-hexagrams [SHUFFLE_HEXAGRAMS]
                        shuffle hexagram order
  -d DECRYPT, --decrypt DECRYPT
                        decrypt message
  -bk BASE_KEY, --base-key BASE_KEY
                        base key for decryption
  -hk HEXAGRAM_KEY, --hexagram-key HEXAGRAM_KEY
                        hexagram key for decryption
  -b BASE, --base BASE  target base {16, 32, 64}
  -oh [OFFSET_HEXAGRAMS], --offset-hexagrams [OFFSET_HEXAGRAMS]
                        offset hexagram slice for base {16, 32}
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
$ ./iching.py -sb -sh -e 'test' > test.txt
Base64 Key: zt+3dUFZig8RXjfeq0oxDySCWMvVulc2AQKYsk95mwbB17T/6h4ONpPnHaJrGILE
Hexagram Key: ䷚䷏䷾䷮䷕䷖䷼䷦䷡䷴䷙䷬䷑䷣䷷䷞䷩䷃䷛䷸䷠䷫䷯䷧䷄䷳䷈䷐䷭䷗䷻䷊䷌䷽䷰䷝䷜䷀䷟䷿䷺䷘䷲䷂䷱䷶䷤䷢䷥䷎䷪䷇䷓䷒䷉䷋䷨䷅䷍䷵䷔䷹䷆䷁
$ cat test.txt
䷁䷙䷲䷌䷁䷴
```

## Examples

### Encrypt/decrypt hexagrams (no shuffling)

```bash
$ ./iching.py -e 'test'
䷝䷆䷕䷳䷝䷀
$ ./iching.py -d '䷝䷆䷕䷳䷝䷀'
test
```

### Encrypt/decrypt file as hexagrams (no shuffling)

```bash
$ ./iching.py -ef 'some-file.extension' > secret.iching
$ ./iching.py -df 'secret.iching' > decrypted.extension
```

### Encrypt/decrypt to different ngrams (no shuffling)

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

### Encrypt/decrypt hexagrams in a different base (no shuffling)

```bash
$ ./iching.py -b32 -e 'test'
䷎䷑䷒䷗䷆䷝䷀
$ ./iching.py -b32 -d '䷎䷑䷒䷗䷆䷝䷀'
test
```

### Encrypt/decrypt hexagrams in base16/32 with offset hexagrams (no shuffling)

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

## Symbols and Meaning

Symbol | ALT Code  | ALT X Code | Symbol Name | HTML Entity DEC | HTML Entity HEX | Unicode Code Point
---    | ---       | ---        | ---         | ---             | ---             | ---
☰     | ALT 9776  | 2630 ALT X | Trigram for heaven, sky, 乾 qián | &#9776 | &#x2630 | U+2630
☱     | ALT 9777  | 2631 ALT X | Trigram for lake, marsh, 兌 duì | &#9777 | &#x2631 | U+2631
☲     | ALT 9778  | 2632 ALT X | Trigram for fire, 離 lí | &#9778 | &#x2632	 | U+2632
☳     | ALT 9779  | 2633 ALT X | Trigram for thunder, 震 zhèn | &#9779 | &#x2633 | U+2633
☴     | ALT 9780  | 2634 ALT X | Trigram for wind, 巽 xùn | &#9780 | &#x2634 | U+2634
☵     | ALT 9781  | 2635 ALT X | Trigram for water, 坎 kǎn | &#9781 | &#x2635 | U+2635
☶     | ALT 9782  | 2636 ALT X | Trigram for mountain, 艮 gèn | &#9782 | &#x2636 | U+2636
☷     | ALT 9783  | 2637 ALT X | Trigram for earth, 坤 kūn | &#9783 | &#x2637 | U+2637
⚊     | ALT 9866  | 268A ALT X | Monogram for yang | &#9866 | &#x268A | U+268A
⚋     | ALT 9867  | 268B ALT X | Monogram for yin | &#9867 | &#x268B | U+268B
⚌     | ALT 9868  | 268C ALT X | Digram for greater yang | &#9868 | &#x268C | U+268C
⚍     | ALT 9869  | 268D ALT X | Digram for lesser yin | &#9869 | &#x268D | U+268D
⚎     | ALT 9870  | 268E ALT X | Digram for lesser yang | &#9870 | &#x268E | U+268E
⚏     | ALT 9871  | 268F ALT X | Digram for greater yin | &#9871 | &#x268F | U+268F
䷀     | ALT 19904 | 4DC0 ALT X | Hexagram for the creative heaven, 乾 qián, force | &#19904 | &#x4DC0 | U+4DC0
䷁     | ALT 19905 | 4DC1 ALT X | Hexagram for the receptive earth, 坤 kūn, field | &#19905 | &#x4DC1 | U+4DC1
䷂     | ALT 19906 | 4DC2 ALT X | Hexagram for difficulty at the beginning, 屯 zhūn, sprouting | &#19906 | &#x4DC2 | U+4DC2
䷃     | ALT 19907 | 4DC3 ALT X | Hexagram for youthful folly, 蒙 méng, enveloping | &#19907 | &#x4DC3 | U+4DC3
䷄     | ALT 19908 | 4DC4 ALT X | Hexagram for waiting, 需 xū, attending | &#19908 | &#x4DC4 | U+4DC4
䷅     | ALT 19909 | 4DC5 ALT X | Hexagram for conflict, 訟 sòng, arguing | &#19909 | &#x4DC5 | U+4DC5
䷆     | ALT 19910 | 4DC6 ALT X | Hexagram for the army, 師 shī, leading	 | &#19910 | &#x4DC6 | U+4DC6
䷇     | ALT 19911 | 4DC7 ALT X | Hexagram for holding together, 比 bǐ, grouping | &#19911 | &#x4DC7 | U+4DC7
䷈     | ALT 19912 | 4DC8 ALT X | Hexagram for small taming, 小畜 xiǎo chù, small accumulating | &#19912 | &#x4DC8 | U+4DC8
䷉     | ALT 19913 | 4DC9 ALT X | Hexagram for treading, 履 lǚ, treading	 | &#19913 | &#x4DC9 | U+4DC9
䷊     | ALT 19914 | 4DCA ALT X | Hexagram for peace, 泰 tài, pervading | &#19914 | &#x4DCA | U+4DCA
䷋     | ALT 19915 | 4DCB ALT X | Hexagram for standstill, 否 pǐ, obstruction | &#19915 | &#x4DCB | U+4DCB
䷌     | ALT 19916 | 4DCC ALT X | Hexagram for fellowship, 同人 tóng rén, concording people | &#19916 | &#x4DCC | U+4DCC
䷍     | ALT 19917 | 4DCD ALT X | Hexagram for great possession, 大有 dà yǒu, great possessing | &#19917 | &#x4DCD | U+4DCD
䷎     | ALT 19918 | 4DCE ALT X | Hexagram for modesty, 謙 qiān, humbling | &#19918 | &#x4DCE | U+4DCE
䷏     | ALT 19919 | 4DCF ALT X | Hexagram for enthusiasm, 豫 yù, providing-for | &#19919 | &#x4DCF | U+4DCF
䷐     | ALT 19920 | 4DD0 ALT X | Hexagram for following, 隨 suí, following | &#19920 | &#x4DD0 | U+4DD0
䷑     | ALT 19921 | 4DD1 ALT X | Hexagram for work on the decayed, 蠱 gǔ, correcting | &#19921 | &#x4DD1 | U+4DD1
䷒     | ALT 19922 | 4DD2 ALT X | Hexagram for approach, 臨 lín, nearing	 | &#19922 | &#x4DD2 | U+4DD2
䷓     | ALT 19923 | 4DD3 ALT X | Hexagram for contemplation, 觀 guān, viewing | &#19923 | &#x4DD3 | U+4DD3
䷔     | ALT 19924 | 4DD4 ALT X | Hexagram for biting through, 噬嗑 shì kè, gnawing bite | &#19924 | &#x4DD4 | U+4DD4
䷕     | ALT 19925 | 4DD5 ALT X | Hexagram for grace, 賁 bì, adorning | &#19925 | &#x4DD5 | U+4DD5
䷖     | ALT 19926 | 4DD6 ALT X | Hexagram for splitting apart, 剝 bō, stripping | &#19926 | &#x4DD6 | U+4DD6
䷗     | ALT 19927 | 4DD7 ALT X | Hexagram for return, 復 fù, returning | &#19927 | &#x4DD7 | U+4DD7
䷘     | ALT 19928 | 4DD8 ALT X | Hexagram for innocence, 無妄 wú wàng, without embroiling | &#19928 | &#x4DD8 | U+4DD8
䷙     | ALT 19929 | 4DD9 ALT X | Hexagram for great taming, 大畜 dà chù, great accumulating | &#19929 | &#x4DD9 | U+4DD9
䷚     | ALT 19930 | 4DDA ALT X | Hexagram for mouth corners, 頤 yí, swallowing | &#19930 | &#x4DDA | U+4DDA
䷛     | ALT 19931 | 4DDB ALT X | Hexagram for great preponderance, 大過 dà guò, great exceeding | &#19931 | &#x4DDB | U+4DDB
䷜     | ALT 19932 | 4DDC ALT X | Hexagram for the abysmal water, 坎 kǎn, gorge | &#19932 | &#x4DDC | U+4DDC
䷝     | ALT 19933 | 4DDD ALT X | Hexagram for the clinging fire, 離 lí, radiance | &#19933 | &#x4DDD | U+4DDD
䷞     | ALT 19934 | 4DDE ALT X | Hexagram for influence, 咸 xián, conjoining | &#19934 | &#x4DDE | U+4DDE
䷟     | ALT 19935 | 4DDF ALT X | Hexagram for duration, 恆 héng, persevering | &#19935 | &#x4DDF | U+4DDF
䷠     | ALT 19936 | 4DE0 ALT X | Hexagram for retreat, 遯 dùn, retiring	 | &#19936 | &#x4DE0 | U+4DE0
䷡     | ALT 19937 | 4DE1 ALT X | Hexagram for great power, 大壯 dà zhuàng, great invigorating | &#19937 | &#x4DE1 | U+4DE1
䷢     | ALT 19938 | 4DE2 ALT X | Hexagram for progress, 晉 jìn, prospering | &#19938 | &#x4DE2 | U+4DE2
䷣     | ALT 19939 | 4DE3 ALT X | Hexagram for darkening of the light, 明夷 míng yí, darkening of the light | &#19939 | &#x4DE3 | U+4DE3
䷤     | ALT 19940 | 4DE4 ALT X | Hexagram for the family, 家人 jiā rén, dwelling people | &#19940 | &#x4DE4 | U+4DE4
䷥     | ALT 19941 | 4DE5 ALT X | Hexagram for opposition, 睽 kuí, polarising | &#19941 | &#x4DE5 | U+4DE5
䷦     | ALT 19942 | 4DE6 ALT X | Hexagram for obstruction, 蹇 jiǎn, limping | &#19942 | &#x4DE6 | U+4DE6
䷧     | ALT 19943 | 4DE7 ALT X | Hexagram for deliverance, 解 xiè, taking-apart | &#19943 | &#x4DE7 | U+4DE7
䷨     | ALT 19944 | 4DE8 ALT X | Hexagram for decrease, 損 sǔn, diminishing | &#19944 | &#x4DE8 | U+4DE8
䷩     | ALT 19945 | 4DE9 ALT X | Hexagram for increase, 益 yì, augmenting | &#19945	| &#x4DE9 | U+4DE9
䷪     | ALT 19946 | 4DEA ALT X | Hexagram for breakthrough, 夬 guài, displacement | &#19946 | &#x4DEA | U+4DEA
䷫     | ALT 19947 | 4DEB ALT X | Hexagram for coming to meet, 姤 gòu, coupling | &#19947 | &#x4DEB | U+4DEB
䷬     | ALT 19948 | 4DEC ALT X | Hexagram for gathering together, 萃 cuì, clustering | &#19948 | &#x4DEC | U+4DEC
䷭     | ALT 19949 | 4DED ALT X | Hexagram for pushing upward, 升 shēng, ascending | &#19949 | &#x4DED | U+4DED
䷮     | ALT 19950 | 4DEE ALT X | Hexagram for oppression, 困 kùn, confining | &#19950 | &#x4DEE | U+4DEE
䷯     | ALT 19951 | 4DEF ALT X | Hexagram for the well, 井 jǐng, welling | &#19951 | &#x4DEF | U+4DEF
䷰     | ALT 19952 | 4DF0 ALT X | Hexagram for revolution, 革 gé, skinning | &#19952 | &#x4DF0 | U+4DF0
䷱     | ALT 19953 | 4DF1 ALT X | Hexagram for the cauldron, 鼎 dǐng, holding | &#19953 | &#x4DF1 | U+4DF1
䷲     | ALT 19954 | 4DF2 ALT X | Hexagram for the arousing thunder, 震 zhèn, shake | &#19954 | &#x4DF2 | U+4DF2
䷳     | ALT 19955 | 4DF3 ALT X | Hexagram for the keeping still mountain, 艮 gèn, bound | &#19955 | &#x4DF3 | U+4DF3
䷴     | ALT 19956 | 4DF4 ALT X | Hexagram for development, 漸 jiàn, infiltrating | &#19956 | &#x4DF4 | U+4DF4
䷵     | ALT 19957 | 4DF5 ALT X | Hexagram for the marrying maiden, 歸妹 guī mèi, converting the maiden | &#19957 | &#x4DF5 | U+4DF5
䷶     | ALT 19958 | 4DF6 ALT X | Hexagram for abundance, 豐 fēng, abounding | &#19958 | &#x4DF6 | U+4DF6
䷷     | ALT 19959 | 4DF7 ALT X | Hexagram for the wanderer, 旅 lǚ, sojourning | &#19959 | &#x4DF7 | U+4DF7
䷸     | ALT 19960 | 4DF8 ALT X | Hexagram for the gentle wind, 巽 xùn, ground | &#19960 | &#x4DF8 | U+4DF8
䷹     | ALT 19961 | 4DF9 ALT X | Hexagram for the joyous lake, 兌 duì, open | &#19961 | &#x4DF9 | U+4DF9
䷺     | ALT 19962 | 4DFA ALT X | Hexagram for dispersion, 渙 huàn, dispersing | &#19962 | &#x4DFA | U+4DFA
䷻     | ALT 19963 | 4DFB ALT X | Hexagram for limitation, 節 jié, articulating | &#19963 | &#x4DFB | U+4DFB
䷼     | ALT 19964 | 4DFC ALT X | Hexagram for inner truth, 中孚 zhōng fú, center returning | &#19964 | &#x4DFC | U+4DFC
䷽     | ALT 19965 | 4DFD ALT X | Hexagram for small preponderance, 小過 xiǎo guò, small exceeding | &#19965 | &#x4DFD | U+4DFD
䷾     | ALT 19966 | 4DFE ALT X | Hexagram for after completion, 既濟 jì jì, already fording | &#19966 | &#x4DFE | U+4DFE
䷿     | ALT 19967 | 4DFF ALT X | Hexagram for before completion, 未濟 wèi jì, not yet fording | &#19967 | &#x4DFF | U+4DFF
