/*
 * @(#) AttributeTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.markup;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

import junit.framework.Assert;

import org.junit.Test;

public class AttributeTest {
	@Test
	public void test() {
		Attribute attr = new Attribute(null, null);
		Assert.assertEquals("", attr.getValue());
		Assert.assertTrue(attr.isMinimized());

		attr.setValue("test");
		Assert.assertFalse(attr.isMinimized());
	}

	@Test
	public void testSerialize() {
		try {
			Attribute attr = new Attribute("test", " <test>");
			attr.serialize(null);
			attr.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));

			attr.setValue(null);
			attr.serialize(new BufferedWriter(new OutputStreamWriter(System.out)));
		} catch (IOException ioe) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
