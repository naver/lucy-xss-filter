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
