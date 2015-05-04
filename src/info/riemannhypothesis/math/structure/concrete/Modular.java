/**
 * 
 */
package info.riemannhypothesis.math.structure.concrete;

import info.riemannhypothesis.math.structure.Ring;

import java.math.BigInteger;

/**
 * @author Markus Schepke
 * @date 4 Jan 2015
 */
public class Modular implements Ring<Modular> {

    public final BigInteger m;
    public final BigInteger n;

    protected Modular       neg;

    public Modular(BigInteger n, BigInteger m) {
        this.m = m;
        BigInteger temp = n;
        while (temp.compareTo(BigInteger.ZERO) < 0) {
            temp = temp.add(m);
        }
        while (temp.compareTo(m) >= 0) {
            temp = temp.subtract(m);
        }
        this.n = temp;
    }

    @Override
    public Modular add(Modular that) {
        if (!this.m.equals(that.m)) {
            throw new IllegalArgumentException();
        }
        return new Modular(this.n.add(that.n), m);
    }

    @Override
    public Modular subtract(Modular that) {
        if (!this.m.equals(that.m)) {
            throw new IllegalArgumentException();
        }
        return new Modular(this.n.subtract(that.n), m);
    }

    @Override
    public Modular negate() {
        if (neg != null) {
            return neg;
        }
        neg = new Modular(BigInteger.ZERO.subtract(n), m);
        return neg;
    }

    @Override
    public Modular multiply(Modular that) {
        if (!this.m.equals(that.m)) {
            throw new IllegalArgumentException();
        }
        return new Modular(this.n.multiply(that.n), m);
    }

    @Override
    public boolean isZero() {
        return n.equals(BigInteger.ZERO);
    }

    @Override
    public boolean isOne() {
        return n.equals(BigInteger.ONE);
    }

}
