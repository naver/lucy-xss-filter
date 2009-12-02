package com.nhncorp.lucy.security.xss.markup.rule;

import org.junit.Assert;
import org.junit.Test;

public class CharCodeSetTest {
	@Test
	public void testNull() {
		CharCodeSet c = new CharCodeSet(new char[] {'0', '1', '2'});

		try {
			c.flip(0);
			c.setAll(null);
			c.setAll(c);
			c.flipAll(null);
			c.flipAll(c);
			Assert.assertEquals(-1, c.matchPos(new CharArraySegment("012")));
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
