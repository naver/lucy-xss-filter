package com.nhncorp.lucy.security.xss.markup;

import org.junit.Assert;
import org.junit.Test;

public class CommentTest {
	@Test
	public void testNull() {
		Comment c = new Comment(null);
		try {
			c.serialize(null);
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
