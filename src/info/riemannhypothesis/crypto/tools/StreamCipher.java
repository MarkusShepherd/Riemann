package info.riemannhypothesis.crypto.tools;

/**
 * @author Markus Schepke
 * @date 13 Aug 2014
 */
public class StreamCipher implements Cipher {

    private final PseudoRandomGenerator prg;
    private final ByteSequence          seed;

    public StreamCipher(PseudoRandomGenerator prg, ByteSequence seed) {
        this.prg = prg;
        this.seed = seed;
    }

    @Override
    public ByteSequence encrypt(ByteSequence input) {
        ByteSequence key = prg.random(seed);
        if (input.length() > key.length()) {
            throw new IllegalArgumentException(
                    "Input length is longer than key");
        }
        return input.xor(key);
    }

    @Override
    public ByteSequence decrypt(ByteSequence output) {
        return encrypt(output);
    }

}
