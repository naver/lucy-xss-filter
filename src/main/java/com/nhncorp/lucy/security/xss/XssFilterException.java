package com.nhncorp.lucy.security.xss;

/**
 * Xss Filter Exception
 * 
 * @author nhn
 *
 */
public class XssFilterException extends RuntimeException {
	private static final long serialVersionUID = 2560642935469511816L;

	/**
	 * {@inheritDoc}
	 */
	public XssFilterException(String message) {
		super(message);
	}
}
