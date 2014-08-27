package info.riemannhypothesis.crypto.tools;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Markus Schepke
 * @date 21 Aug 2014
 */
public class DES extends BlockCipher {

    public final static Function<ByteSequence, ByteSequence> IP             = functionFromBitTable(new int[] {
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
            53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48,
            40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44,
            36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6               });

    public final static Function<ByteSequence, ByteSequence> FP             = functionFromBitTable(new int[] {
            39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
            5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3,
            43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,
            9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24                });

    public final static Function<ByteSequence, ByteSequence> E              = functionFromBitTable(new int[] {
            31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12,
            13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23,
            24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0                      });

    public final static Function<ByteSequence, ByteSequence> P              = functionFromBitTable(new int[] {
            15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7,
            23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24             });

    public final static Function<ByteSequence, ByteSequence> PC1            = functionFromBitTable(new int[] {
            56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50,
            42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14,
            6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4,
            27, 19, 11, 3                                                  });

    public final static Function<ByteSequence, ByteSequence> PC2            = functionFromBitTable(new int[] {
            13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7,
            15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32,
            47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31             });

    public final static Function<ByteSequence, ByteSequence> LEFT_ROT_1     = functionFromBitTable(new int[] {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, 26, 27, 0, 29, 30, 31, 32, 33, 34, 35, 36,
            37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 28                                                     });

    public final static Function<ByteSequence, ByteSequence> LEFT_ROT_2     = functionFromBitTable(new int[] {
            2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            21, 22, 23, 24, 25, 26, 27, 0, 1, 30, 31, 32, 33, 34, 35, 36, 37,
            38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
            55, 28, 29                                                     });

    public final static byte[]                               LEFT_ROTATIONS = new byte[] {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1                 };

    @SuppressWarnings("unchecked")
    public final static Function<Byte, Byte>[]               S              = (Function<Byte, Byte>[]) new Function<?, ?>[] {
            functionFromLookupTable(new byte[] { 14, 0, 4, 15, 13, 7, 1, 4, 2,
            14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5,
            0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
            15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13 }),
            functionFromLookupTable(new byte[] { 15, 3, 1, 13, 8, 4, 14, 7, 6,
            15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5,
            11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
            5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9 }),
            functionFromLookupTable(new byte[] { 10, 13, 0, 7, 9, 0, 14, 9, 6,
            3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2,
            15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11,
            4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12 }),
            functionFromLookupTable(new byte[] { 7, 13, 13, 8, 14, 11, 3, 5, 0,
            6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4,
            14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
            15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14 }),
            functionFromLookupTable(new byte[] { 2, 14, 12, 11, 4, 2, 1, 12, 7,
            4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14,
            8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15,
            6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3 }),
            functionFromLookupTable(new byte[] { 12, 10, 1, 15, 10, 4, 15, 2,
            9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11,
            5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
            7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13 }),
            functionFromLookupTable(new byte[] { 4, 13, 11, 0, 2, 11, 14, 7,
            15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15,
            6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
            10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12 }),
            functionFromLookupTable(new byte[] { 13, 1, 2, 15, 8, 13, 4, 8, 6,
            10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14,
            12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
            0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11 })        };

    private static boolean                                   strict         = false;
    private final FeistelNetwork                             fn;

    public DES(ByteSequence key) {
        super(8, key);

        if (key.length() != 8) {
            throw new IllegalArgumentException();
        }

        ByteSequence[] keys = keyExpansion(key);

        @SuppressWarnings("unchecked")
        Function<ByteSequence, ByteSequence>[] functions = (Function<ByteSequence, ByteSequence>[]) new Function<?, ?>[keys.length];

        for (int i = 0; i < functions.length; i++) {
            functions[i] = feistelFunction(keys[i]);
        }

        fn = new FeistelNetwork(functions);

    }

    @Override
    public ByteSequence encrypt(ByteSequence input) {

        return FP.apply(fn.encrypt(IP.apply(input)));

    }

    @Override
    public ByteSequence decrypt(ByteSequence output) {

        return IP.apply(fn.decrypt(FP.apply(output)));

    }

    private static Function<ByteSequence, ByteSequence> feistelFunction(
            final ByteSequence key) {

        if (key.length() != 6) {
            throw new IllegalArgumentException();
        }

        return new Function<ByteSequence, ByteSequence>() {
            @Override
            public ByteSequence apply(ByteSequence arg) {

                if (arg.length() != 4) {
                    throw new IllegalArgumentException();
                }

                ByteSequence expanded = E.apply(arg).xor(key);

                byte[] result = new byte[4];

                for (int i = 0; i < 8; i++) {
                    byte temp = S[i].apply((byte) expanded.bitRange(i * 6,
                            (i + 1) * 6));
                    if (i % 2 == 0) {
                        result[i / 2] |= (temp << 4);
                    } else {
                        result[i / 2] |= temp;
                    }
                }

                return P.apply(new ByteSequence(result));
            }
        };
    }

    private static ByteSequence[] keyExpansion(ByteSequence key) {
        if (key.length() != 8) {
            throw new IllegalArgumentException("Keylength must be 64 bits");
        }

        if (strict) {
            for (int i = 0; i < key.length(); i++) {
                if ((Integer.bitCount(key.byteAt(i)) % 2) != 1) {
                    throw new IllegalArgumentException("Parity of byte " + i
                            + " is wrong");
                }
            }
        }

        ByteSequence pc1 = PC1.apply(key);

        ByteSequence[] result = new ByteSequence[16];

        for (int i = 0; i < result.length; i++) {
            if (LEFT_ROTATIONS[i] == 1) {
                pc1 = LEFT_ROT_1.apply(pc1);
            } else {
                pc1 = LEFT_ROT_2.apply(pc1);
            }
            result[i] = PC2.apply(pc1);
        }

        return result;
    }

    private static Function<ByteSequence, ByteSequence> functionFromBitTable(
            final int[] table) {
        return new Function<ByteSequence, ByteSequence>() {
            @Override
            public ByteSequence apply(ByteSequence arg) {
                int l = table.length;
                byte[] result = new byte[l / 8];

                int b = 0;
                int s = 7;

                for (int i = 0; i < l; i++) {
                    byte bit = arg.bitAt(table[i]);
                    if (bit != 0) {
                        result[b] |= (1 << s);
                    }
                    s--;
                    if (s < 0) {
                        b++;
                        s = 7;
                    }
                }

                return new ByteSequence(result);
            }
        };
    }

    private static Function<Byte, Byte> functionFromLookupTable(
            final byte[] table) {
        return new Function<Byte, Byte>() {
            @Override
            public Byte apply(Byte arg) {
                return table[arg];
            }
        };
    }

    public static void main(String[] args) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        /* int[] table = new int[] { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
         * 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
         * 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29,
         * 32 }; for (int i = 0; i < table.length; i++) { table[i]--; } */
        // System.out.println(Arrays.toString(table));
        // System.out.println(table.length);

        // Function<ByteSequence, ByteSequence> test =
        // functionFromBitTable(table);

        // ByteSequence b = ByteSequence.fromInt(
        // (int) (Math.random() * Integer.MAX_VALUE), 4);
        ByteSequence b = ByteSequence.fromLong(
                (long) (Math.random() * Long.MAX_VALUE), 8);
        // System.out.println(b.toNumString(2, " "));
        // ByteSequence c = test.apply(b);
        // System.out.println(c.toNumString(2, " "));
        // ByteSequence d = LEFT_ROT_2.apply(b);
        // System.out.println(d.toNumString(2, " "));
        // System.out.println(c.equals(d));

        /* byte input = (byte) (Math.random() * 64);
         * System.out.println(Integer.toBinaryString(input));
         * 
         * for (int i = 0; i < S.length; i++) { byte output = S[i].apply(input);
         * System.out.println(output); } */

        ByteSequence key = b;
        ByteSequence message = b;

        DES des = new DES(key);
        ByteSequence cipher = des.encrypt(message);
        ByteSequence decrypted = des.decrypt(cipher);

        System.out.println(message.toNumString(2, " "));
        System.out.println(cipher.toNumString(2, " "));
        System.out.println(decrypted.toNumString(2, " "));

        javax.crypto.Cipher x = javax.crypto.Cipher.getInstance("DES");
        final SecretKeySpec secretKey = new SecretKeySpec(key.getByteArray(),
                "DES");
        x.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = x.doFinal(message.getByteArray());
        ByteSequence wrapper = new ByteSequence(encrypted);
        System.out.println(wrapper.toNumString(2, " "));
    }
}
