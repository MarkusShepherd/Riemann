/**
 * 
 */
package info.riemannhypothesis.math.structure.concrete;

import info.riemannhypothesis.math.structure.Field;

import java.math.BigInteger;

/**
 * @author Markus Schepke
 * @date 4 Jan 2015
 */
public class PrimeField implements Field<PrimeField> {

    /**
     * @param n
     * @param m
     */
    public PrimeField(BigInteger n, BigInteger m) {
        // super(n, m);
        // TODO Auto-generated constructor stub
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

    @Override
    public PrimeField negate() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public PrimeField subtract(PrimeField that) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isZero() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public PrimeField add(PrimeField that) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public PrimeField multiply(PrimeField that) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isOne() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public PrimeField inverse() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public PrimeField divide(PrimeField that) {
        // TODO Auto-generated method stub
        return null;
    }

}
