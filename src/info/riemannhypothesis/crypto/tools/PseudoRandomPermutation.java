package info.riemannhypothesis.crypto.tools;

public abstract class PseudoRandomPermutation extends PseudoRandomFunction implements Cipher {

	public final int blockLength;

	public PseudoRandomPermutation(int keyLength, int blockLength) {
		super(keyLength, blockLength, blockLength);
		this.blockLength = blockLength;
	}

	public abstract ByteSequence decrypt(ByteSequence output);

}
