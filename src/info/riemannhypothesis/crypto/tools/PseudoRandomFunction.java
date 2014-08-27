package info.riemannhypothesis.crypto.tools;

public abstract class PseudoRandomFunction {

	public final int keyLength;
	public final int inputLength;
	public final int outputLength;

	public PseudoRandomFunction(int keyLength, int inputLength, int outputLength) {
		this.keyLength = keyLength;
		this.inputLength = inputLength;
		this.outputLength = outputLength;
	}

	public abstract ByteSequence encrypt(ByteSequence input);

}
