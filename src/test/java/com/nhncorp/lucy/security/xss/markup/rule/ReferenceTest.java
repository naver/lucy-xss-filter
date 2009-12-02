package com.nhncorp.lucy.security.xss.markup.rule;

import org.junit.Assert;
import org.junit.Test;

import com.nhncorp.lucy.security.xss.markup.rule.ParsingRule.UNARY;

public class ReferenceTest {
	@Test
	public void testNull() {
		Reference r = new Reference("");
		Assert.assertNotNull(r.getRuleName());
		r.setUnary(UNARY.OPTION);
		Assert.assertEquals(-1, r.matchPos(null, ParsingGrammar.getInstance()));
		Assert.assertNull(r.getFirstNonOptTerminals(ParsingGrammar.getInstance()));
	}
}
