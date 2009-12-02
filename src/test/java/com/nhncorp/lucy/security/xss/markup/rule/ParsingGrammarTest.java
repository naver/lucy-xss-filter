package com.nhncorp.lucy.security.xss.markup.rule;

import org.junit.Assert;
import org.junit.Test;

public class ParsingGrammarTest {

	@Test
	public void testNull() {
		Assert.assertNull(ParsingGrammar.getInstance().tokenize(null));
	}
}
