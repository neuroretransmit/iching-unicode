class ANSIColor:
    MAGENTA = '\033[95m'
    RED = '\033[91m'
    YELLOW = '\033[33m'
    ENDC = '\033[0m'


ENCODING = 'utf-8'

B16 = 16
B32 = 32
B64 = 64
BASE_DEFAULT_CHARSETS = {
    B16: '0123456789ABCDEF',
    B32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    B64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
}

MONOGRAMS = '⚊⚋'
DIGRAMS = '⚌⚍⚎⚏'
TRIGRAMS = '☰☱☲☳☴☵☶☷'
HEXAGRAMS = '䷀䷁䷂䷃䷄䷅䷆䷇䷈䷉䷊䷋䷌䷍䷎䷏䷐䷑䷒䷓䷔䷕䷖䷗䷘䷙䷚䷛䷜䷝䷞䷟' \
            '䷠䷡䷢䷣䷤䷥䷦䷧䷨䷩䷪䷫䷬䷭䷮䷯䷰䷱䷲䷳䷴䷵䷶䷷䷸䷹䷺䷻䷼䷽䷾䷿'
DIGRAM_TO_MONOGRAM_MAPPING = {'⚌': '⚊⚊', '⚍': '⚋⚊', '⚎': '⚊⚋', '⚏': '⚋⚋'}
HEXAGRAM_TO_TRIGRAM_MAPPING = {
    '䷀': '☰☰', '䷁': '☷☷', '䷂': '☵☳', '䷃': '☶☵', '䷄': '☵☰', '䷅': '☰☵', '䷆': '☷☵', '䷇': '☵☷',
    '䷈': '☴☰', '䷉': '☰☱', '䷊': '☷☰', '䷋': '☰☷', '䷌': '☰☲', '䷍': '☲☰', '䷎': '☷☶', '䷏': '☳☷',
    '䷐': '☱☳', '䷑': '☶☴', '䷒': '☷☱', '䷓': '☴☷', '䷔': '☲☳', '䷕': '☶☲', '䷖': '☶☷', '䷗': '☷☳',
    '䷘': '☰☳', '䷙': '☶☰', '䷚': '☶☳', '䷛': '☱☴', '䷜': '☵☵', '䷝': '☲☲', '䷞': '☱☶', '䷟': '☳☴',
    '䷠': '☰☶', '䷡': '☳☰', '䷢': '☲☷', '䷣': '☷☲', '䷤': '☴☲', '䷥': '☲☱', '䷦': '☵☶', '䷧': '☳☵',
    '䷨': '☶☱', '䷩': '☴☳', '䷪': '☱☰', '䷫': '☰☴', '䷬': '☱☷', '䷭': '☷☴', '䷮': '☱☵', '䷯': '☵☴',
    '䷰': '☱☲', '䷱': '☲☴', '䷲': '☳☳', '䷳': '☶☶', '䷴': '☴☶', '䷵': '☳☱', '䷶': '☳☲', '䷷': '☲☶',
    '䷸': '☴☴', '䷹': '☱☱', '䷺': '☴☵', '䷻': '☵☱', '䷼': '☴☱', '䷽': '☳☶', '䷾': '☵☲', '䷿': '☲☵'
}
TRIGRAM_TO_HEXAGRAM_MAPPING = {v: k for k, v in HEXAGRAM_TO_TRIGRAM_MAPPING.items()}
HEXAGRAM_TO_DIGRAM_MAPPING = {
    '䷀': '⚌⚌⚌', '䷁': '⚏⚏⚏', '䷂': '⚍⚏⚍', '䷃': '⚎⚏⚎', '䷄': '⚍⚍⚌', '䷅': '⚌⚎⚎', '䷆': '⚏⚏⚎', '䷇': '⚍⚏⚏',
    '䷈': '⚌⚍⚌', '䷉': '⚌⚎⚌', '䷊': '⚏⚍⚌', '䷋': '⚌⚎⚏', '䷌': '⚌⚌⚍', '䷍': '⚎⚌⚌', '䷎': '⚏⚍⚏', '䷏': '⚏⚎⚏',
    '䷐': '⚍⚎⚍', '䷑': '⚎⚍⚎', '䷒': '⚏⚏⚌', '䷓': '⚌⚏⚏', '䷔': '⚎⚎⚍', '䷕': '⚎⚍⚍', '䷖': '⚎⚏⚏', '䷗': '⚏⚏⚍',
    '䷘': '⚌⚎⚍', '䷙': '⚎⚍⚌', '䷚': '⚎⚏⚍', '䷛': '⚍⚌⚎', '䷜': '⚍⚏⚎', '䷝': '⚎⚌⚍', '䷞': '⚍⚌⚏', '䷟': '⚏⚌⚎',
    '䷠': '⚌⚌⚏', '䷡': '⚏⚌⚌', '䷢': '⚎⚎⚏', '䷣': '⚏⚍⚍', '䷤': '⚌⚍⚍', '䷥': '⚎⚎⚌', '䷦': '⚍⚍⚏', '䷧': '⚏⚎⚎',
    '䷨': '⚎⚏⚌', '䷩': '⚌⚏⚍', '䷪': '⚍⚌⚌', '䷫': '⚌⚌⚎', '䷬': '⚍⚎⚏', '䷭': '⚏⚍⚎', '䷮': '⚍⚎⚎', '䷯': '⚍⚍⚎',
    '䷰': '⚍⚌⚍', '䷱': '⚎⚌⚎', '䷲': '⚏⚎⚍', '䷳': '⚎⚍⚏', '䷴': '⚌⚍⚏', '䷵': '⚏⚎⚌', '䷶': '⚏⚌⚍', '䷷': '⚎⚌⚏',
    '䷸': '⚌⚍⚎', '䷹': '⚍⚎⚌', '䷺': '⚌⚏⚎', '䷻': '⚍⚏⚌', '䷼': '⚌⚏⚌', '䷽': '⚏⚌⚏', '䷾': '⚍⚍⚍', '䷿': '⚎⚎⚎'
}
DIGRAM_TO_HEXAGRAM_MAPPING = {v: k for k, v in HEXAGRAM_TO_DIGRAM_MAPPING.items()}
HEXAGRAM_TO_MONOGRAM_MAPPING = {k: ''.join(DIGRAM_TO_MONOGRAM_MAPPING[c] for c in v)
                                for k, v in HEXAGRAM_TO_DIGRAM_MAPPING.items()}
MONOGRAM_TO_HEXAGRAM_MAPPING = {v: k for k, v in HEXAGRAM_TO_MONOGRAM_MAPPING.items()}
NGRAMS_ENCRYPT_MAPPING = {
    'mono': HEXAGRAM_TO_MONOGRAM_MAPPING,
    'di': HEXAGRAM_TO_DIGRAM_MAPPING,
    'tri': HEXAGRAM_TO_TRIGRAM_MAPPING,
    'hex': None
}
NGRAMS_DECRYPT_MAPPING = {
    'mono': MONOGRAM_TO_HEXAGRAM_MAPPING,
    'di': DIGRAM_TO_HEXAGRAM_MAPPING,
    'tri': TRIGRAM_TO_HEXAGRAM_MAPPING,
    'hex': None
}
NGRAM_CHAR_LEN = {
    'mono': 6,
    'di': 3,
    'tri': 2,
    'hex': 1
}
