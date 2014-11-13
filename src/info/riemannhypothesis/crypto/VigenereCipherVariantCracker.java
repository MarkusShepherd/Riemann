package info.riemannhypothesis.crypto;

import info.riemannhypothesis.crypto.tools.ByteSequence;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Markus Schepke
 * @date 12 Nov 2014
 */
public class VigenereCipherVariantCracker {

    public static final double[]       FREQ_EN      = new double[] { 0.08167,
            0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
            0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
            0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978,
            0.02360, 0.00150, 0.01974, 0.00074     };
    public static final Set<Character> ALLOWED_CHAR = new HashSet<Character>(
                                                            Arrays.asList('a',
                                                                    'b', 'c',
                                                                    'd', 'e',
                                                                    'f', 'g',
                                                                    'h', 'i',
                                                                    'j', 'k',
                                                                    'l', 'm',
                                                                    'n', 'o',
                                                                    'p', 'q',
                                                                    'r', 's',
                                                                    't', 'u',
                                                                    'v', 'w',
                                                                    'x', 'y',
                                                                    'z', 'A',
                                                                    'B', 'C',
                                                                    'D', 'E',
                                                                    'F', 'G',
                                                                    'H', 'I',
                                                                    'J', 'K',
                                                                    'L', 'M',
                                                                    'N', 'O',
                                                                    'P', 'Q',
                                                                    'R', 'S',
                                                                    'T', 'U',
                                                                    'V', 'W',
                                                                    'X', 'Y',
                                                                    'Z', '.',
                                                                    ',', '/',
                                                                    '\\', '?',
                                                                    '!', ' ',
                                                                    ':', ';',
                                                                    '\'', '"',
                                                                    '(', ')'));

    public static void main(String[] args) {

        int maxKeyLength = Integer.parseInt(args[0], 10);
        ByteSequence c = ByteSequence.fromHexString(args[1]);
        System.out.println("Cipher text: " + c.toHexString(" "));

        int keyLength = guessKeyLength(c, maxKeyLength);
        System.out.println("Guessed key length: " + keyLength);

        ByteSequence key = guessKey(c, keyLength);
        System.out.println("Guessed key: " + key.toHexString(" "));

        VigenereCipherVariant vcv = new VigenereCipherVariant();
        ByteSequence m = vcv.decrypt(key, c);
        System.out.println("Plaintext: " + m.toString());
    }

    public static double[] countBytes(ByteSequence input) {
        return countBytes(input, 0, 1);
    }

    public static double[] countBytes(ByteSequence input, int start, int incr) {
        int total = 0;
        int[] count = new int[256];

        for (int i = start; i < input.length(); i += incr) {
            byte t = input.byteAt(i);
            int b = t < 0 ? t + 256 : t;
            count[b]++;
            total++;
        }

        double[] result = new double[256];

        for (int i = 0; i < 256; i++) {
            result[i] = (double) count[i] / total;
        }

        return result;
    }

    public static double[] countLetters(ByteSequence input) {
        return countLetters(input, 0, 1, (byte) 0);
    }

    public static double[] countLetters(ByteSequence input, int start,
            int incr, byte shift) {
        int total = 0;
        int[] count = new int[26];

        for (int i = start; i < input.length(); i += incr) {
            byte t = (byte) (input.byteAt(i) ^ shift);
            int b = t < 0 ? t + 256 : t;
            char c = (char) Character.toLowerCase(b);
            if (!ALLOWED_CHAR.contains(c)) {
                return null;
            }
            if (c >= 'a' && c <= 'z') {
                count[c - 'a']++;
                total++;
            }
        }

        double[] result = new double[26];

        for (int i = 0; i < 26; i++) {
            result[i] = (double) count[i] / total;
        }

        return result;
    }

    public static double getDistributionScore(double[] input) {
        return getDistributionScore(input, input);
    }

    public static double getDistributionScore(double[] a, double[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException();
        }
        double result = 0;
        for (int i = 0; i < a.length; i++) {
            result += a[i] * b[i];
        }
        return result / b.length;
    }

    public static int guessKeyLength(ByteSequence c, int maxKeyLength) {
        double max = Double.NEGATIVE_INFINITY;
        int maxLength = 0;
        for (int l = 1; l < Math.min(maxKeyLength, c.length()); l++) {
            Double[] scores = new Double[l];
            for (int i = 0; i < l; i++) {
                scores[i] = getDistributionScore(countBytes(c, i, l));
            }
            double tMax = avg(scores);
            // TODO: try other values? min, max, scores[0] etc
            if (tMax > max) {
                max = tMax;
                maxLength = l;
            }
        }
        return maxLength;
    }

    public static byte guessKeyByte(ByteSequence c, int start, int keyLength) {
        double max = 0;
        byte shift = 0;
        for (byte key = Byte.MIN_VALUE; key < Byte.MAX_VALUE; key++) {
            final double[] countLetters = countLetters(c, start, keyLength, key);
            if (countLetters == null) {
                continue;
            }
            double score = getDistributionScore(FREQ_EN, countLetters);
            if (score > max) {
                max = score;
                shift = key;
            }
        }
        return shift;
    }

    public static ByteSequence guessKey(ByteSequence c, int keyLength) {
        byte[] key = new byte[keyLength];
        for (int i = 0; i < key.length; i++) {
            key[i] = guessKeyByte(c, i, keyLength);
        }
        return new ByteSequence(key);
    }

    public static <T extends Comparable<T>> T max(T[] input) {
        return max(input, 0, input.length);
    }

    public static <T extends Comparable<T>> T max(T[] input, int from, int to) {
        final int l = to - from;
        if (l <= 0) {
            throw new IllegalArgumentException();
        }
        if (l == 1) {
            return input[from];
        }
        if (l == 2) {
            return max(input[from], input[from + 1]);
        }
        int split = l / 2 + from;
        return max(max(input, from, split), max(input, split, to));
    }

    public static <T extends Comparable<T>> T max(T a, T b) {
        if (a.compareTo(b) < 0) {
            return b;
        } else {
            return a;
        }
    }

    public static <T extends Comparable<T>> T min(T[] input) {
        return min(input, 0, input.length);
    }

    public static <T extends Comparable<T>> T min(T[] input, int from, int to) {
        final int l = to - from;
        if (l <= 0) {
            throw new IllegalArgumentException();
        }
        if (l == 1) {
            return input[from];
        }
        if (l == 2) {
            return min(input[from], input[from + 1]);
        }
        int split = l / 2 + from;
        return min(min(input, from, split), min(input, split, to));
    }

    public static <T extends Comparable<T>> T min(T a, T b) {
        if (a.compareTo(b) < 0) {
            return a;
        } else {
            return b;
        }
    }

    public static Double avg(Double[] input) {
        double sum = 0;
        for (int i = 0; i < input.length; i++) {
            sum += input[i];
        }
        return sum / input.length;
    }
}
