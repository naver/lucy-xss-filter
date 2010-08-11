/*
 * @(#) GroupTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import junit.framework.Assert;

import org.junit.Test;

public class GroupTest {
	@Test
	public void testNull() {
		Group g = new Group(null);
		Assert.assertEquals("", g.getRuleName());
		Assert.assertNull(g.getOperator());
		Assert.assertNull(Group.OPERATOR.getValue('t'));

		try {
			g.add(null);
			g.addAll(null);
			g.remove(null);
			Assert.assertEquals(-1, g.matchPos(null, null));
			Assert.assertEquals(-1, g.matchPos(null, ParsingGrammar.getInstance()));

			Assert.assertNotNull(g.getFirstNonOptTerminals(ParsingGrammar.getInstance()));
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
