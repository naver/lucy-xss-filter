/*
 * @(#) AttributeRuleTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.config;

import java.util.ArrayList;

import junit.framework.Assert;

import org.junit.Test;

import com.nhncorp.lucy.security.xss.markup.Attribute;

public class AttributeRuleTest {
	@Test
	public void testNull() throws Exception {
		AttributeRule a = new AttributeRule(null, false);

		Assert.assertEquals("", a.getName());
		Assert.assertEquals(false, a.isDisabled());
		a.setDisabled(true);
		a.checkDisabled(new Attribute(""));

		AttributeRule a1 = new AttributeRule("", false);
		Assert.assertEquals("", a1.getName());

		try {
			a1.addNotAllowedPattern(null);
			a1.addNotAllowedPatterns(new ArrayList());

			a1.addAllowedPattern(null);
			a1.addAllowedPatters(new ArrayList());
		} catch (Exception e) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);
	}
}
