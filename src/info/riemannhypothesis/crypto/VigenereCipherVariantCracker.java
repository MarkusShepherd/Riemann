package info.riemannhypothesis.crypto;

import info.riemannhypothesis.crypto.tools.ByteSequence;

/**
 * @author Markus Schepke
 * @date 12 Nov 2014
 */
public class VigenereCipherVariantCracker {

    public static void main(String[] args) {
        ByteSequence c = ByteSequence.fromHexString(args[0]);
        int keyLength = guessKeyLength(c, 14);
        System.out.println(keyLength);
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

    public static double getDistributionScore(double[] input) {
        double result = 0;
        for (int i = 0; i < input.length; i++) {
            result += input[i] * input[i];
        }
        return result / input.length;
    }

    public static int guessKeyLength(ByteSequence c, int maxKeyLength) {
        double max = Double.NEGATIVE_INFINITY;
        int maxLength = 0;
        for (int l = 1; l < Math.min(maxKeyLength, c.length()); l++) {
            double[] scores = new double[l];
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

    public static double avg(double[] input) {
        double sum = 0;
        for (int i = 0; i < input.length; i++) {
            sum += input[i];
        }
        return sum / input.length;
    }
}
