/*
 * @(#) XssFilterException.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

/**
 * @author nbp
 */
public class XssFilterException extends RuntimeException {
	private static final long serialVersionUID = 2560642935469511816L;

	public XssFilterException(String message) {
		super(message);
	}

}
