package com.nhncorp.lucy.security.xss.markup.rule;

import org.junit.Assert;
import org.junit.Test;

public class CharCodeTest {
	@Test
	public void testNull() {
		CharCode c = new CharCode(' ');
		Assert.assertEquals(-1, c.matchPos(new CharArraySegment("123")));
	}
}
