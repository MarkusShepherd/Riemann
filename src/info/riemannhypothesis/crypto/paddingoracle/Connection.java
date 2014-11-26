package info.riemannhypothesis.crypto.paddingoracle;

import info.riemannhypothesis.crypto.tools.ByteSequence;

/**
 * @author Markus Schepke
 * @date 25 Nov 2014
 */
public abstract class Connection {

    public enum Response {
        SUCCESS, FAIL
    };

    public abstract Response send(ByteSequence message);

    public abstract boolean close();

}
