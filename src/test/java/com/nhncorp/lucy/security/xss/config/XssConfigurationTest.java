package com.nhncorp.lucy.security.xss.config;

import junit.framework.Assert;

import org.junit.Test;

public class XssConfigurationTest {
	@Test
	public void testNull() throws Exception {
		Assert.assertNotNull(XssConfiguration.newInstance("test"));
	}
}
