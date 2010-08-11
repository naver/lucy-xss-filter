/*
 * @(#) XssConfigurationTest.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.config;

import junit.framework.Assert;

import org.junit.Test;

public class XssConfigurationTest {
	@Test
	public void testNull() throws Exception {
		Assert.assertNotNull(XssConfiguration.newInstance("test"));
	}
}
