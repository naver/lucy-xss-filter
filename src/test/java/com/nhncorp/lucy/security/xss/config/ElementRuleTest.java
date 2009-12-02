package com.nhncorp.lucy.security.xss.config;

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Test;

public class ElementRuleTest {
	@Test
	public void testNull() throws Exception {
		ElementRule e = new ElementRule(null);
		Assert.assertEquals("", e.getName());

		ElementRule e1 = new ElementRule("test");
		Assert.assertEquals("test", e1.getName());

		try {
			e1.checkEndTag(null);
			e1.addAllowedAttribute(null);
			e1.addAllowedAttributes(new ArrayList());

			e1.addAllowedElement("");
			e1.addAllowedElement(null);
			e1.addAllowedElements(new ArrayList());

			e1.addListener(null);
		} catch (Exception ex) {
			Assert.assertFalse(false);
		}
		Assert.assertTrue(true);

	}
}
