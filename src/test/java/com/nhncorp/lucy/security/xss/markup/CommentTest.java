/*
 * @(#) CommentTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
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
