package info.riemannhypothesis.crypto.tools;

/**
 * @author Markus Schepke
 * @date 13 Aug 2014
 */
public interface Cipher {

    public ByteSequence encrypt(ByteSequence input);

    public ByteSequence decrypt(ByteSequence output);

}
