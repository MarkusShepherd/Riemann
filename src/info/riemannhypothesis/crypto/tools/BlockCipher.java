package info.riemannhypothesis.crypto.tools;

public abstract class BlockCipher extends PseudoRandomPermutation {

    final ByteSequence key;

    public BlockCipher(int keyLength, ByteSequence key) {
        super(keyLength, key.length());
        this.key = key;
    }

}
