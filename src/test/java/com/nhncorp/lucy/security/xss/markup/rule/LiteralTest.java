/*
 * @(#) LiteralTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import junit.framework.Assert;

import org.junit.Test;

public class LiteralTest {
	@Test
	public void testNull() {
		Literal l = new Literal(null);
		Assert.assertEquals("", l.getLiteral());
	}
}
