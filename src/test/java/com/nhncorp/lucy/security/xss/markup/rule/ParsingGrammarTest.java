/*
 * @(#) ParsingGrammarTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import org.junit.Assert;
import org.junit.Test;

public class ParsingGrammarTest {

	@Test
	public void testNull() {
		Assert.assertNull(ParsingGrammar.getInstance().tokenize(null));
	}
}
