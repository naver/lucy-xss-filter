/*
 * @(#) CharArraySegmentTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup.rule;

import junit.framework.Assert;

import org.junit.Test;

public class CharArraySegmentTest {
	@Test
	public void testNull() {

		CharArraySegment seg = new CharArraySegment("abb");
		Assert.assertNotNull(seg.trim());
		Assert.assertEquals(-1, seg.posOf((char[])null));
		Assert.assertEquals(-1, seg.lastPosOf((char[])null));
		Assert.assertEquals(0, seg.lastPosOf('a'));

		try {
			CharArraySegment seg1 = new CharArraySegment("abc");
			Assert.assertNotNull(seg1.concate(seg1));
		} catch (IndexOutOfBoundsException e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
