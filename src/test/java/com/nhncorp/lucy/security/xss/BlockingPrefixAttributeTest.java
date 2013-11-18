/*
 * @(#)MailBlockingPrefixTest.java $version Mar 6, 2013
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.nhncorp.lucy.security.xss;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author nbp
 */
public class BlockingPrefixAttributeTest {

	@Test
	public void testBlockingPrefix() {
		XssFilter filter = XssFilter.getInstance("lucy-xss-mail.xml");
		String clean = filter.doFilter("<naverxx onmouseover=\"alert('kkk');\"></naverxx>");
		String expected = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><blocking_naverxx></blocking_naverxx>";
		Assert.assertEquals(expected, clean);
		
		String clean2 = filter.doFilter("<iframe onmouseover=\"alert('kkk');\"></iframe>");
		String expected2 = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><blocking_iframe></blocking_iframe>";
		Assert.assertEquals(expected2, clean2);
	}
	 
	
	@Test
	public void testSAXBlockingPrefix() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-mail.xml");
		String clean = filter.doFilter("<iframe onmouseover=\"alert('kkk');\"></iframe>");
		String expected = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><xiframe></xiframe>";
		Assert.assertEquals(expected, clean);
		
	}
	
	
	@Test
	public void testSAXBlockingPrefix2() {
		XssSaxFilter filter = XssSaxFilter.getInstance("lucy-xss-sax-body-mail.xml");
		
		String clean2 = filter.doFilter("<naverxx onmouseover=\"alert('kkk');\"></naverxx>");
		String expected2 = "<!-- Not Allowed Attribute Filtered ( onmouseover=\"alert('kkk');\") --><xnaverxx></xnaverxx>";
		Assert.assertEquals(expected2, clean2);
	}

}
