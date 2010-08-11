/*
 * @(#) MarkupParserTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;

import junit.framework.Assert;

import org.junit.Test;

public class MarkupParserTest {
	@Test
	public void testNull() throws IOException {
		Assert.assertNull(MarkupParser.parse(null));
		Assert.assertEquals("", MarkupParser.toString(null));
		Assert.assertNotNull(MarkupParser.toString(new ArrayList()));
	}
}
