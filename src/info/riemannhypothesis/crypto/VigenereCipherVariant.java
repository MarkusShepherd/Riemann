/**
 * 
 */
package info.riemannhypothesis.crypto;

import info.riemannhypothesis.crypto.tools.ByteSequence;
import info.riemannhypothesis.crypto.tools.Cipher;

/**
 * @author Markus Schepke
 * @date 12 Nov 2014
 */
public class VigenereCipherVariant implements Cipher {

    @Override
    public ByteSequence encrypt(ByteSequence key, ByteSequence input) {
        final int il = input.length();
        final int kl = key.length();
        ByteSequence result = ByteSequence.EMPTY_SEQUENCE;
        for (int i = 0; i < il; i += kl) {
            int from = i;
            int to = i + kl;
            if (to > il) {
                to = il;
            }
            ByteSequence b = input.range(from, to).xor(key);
            result = result.append(b);
        }
        return result;
    }

    @Override
    public ByteSequence decrypt(ByteSequence key, ByteSequence output) {
        return this.encrypt(key, output);
    }

    public static void main(String[] args) {
        VigenereCipherVariant vcv = new VigenereCipherVariant();
        ByteSequence k = ByteSequence.fromHexString(args[0]);
        System.out.println(k.toHexString(" "));
        ByteSequence m = new ByteSequence(args[1]);
        System.out.println(m.toHexString(" "));
        ByteSequence c = vcv.encrypt(k, m);
        System.out.println(c.toHexString(" "));
        ByteSequence d = vcv.decrypt(k, c);
        System.out.println(d.toHexString(" "));
        System.out.println(d.toString());
    }

}
